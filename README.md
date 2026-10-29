# NAS Gate

An open/close security gate for a Synology NAS, in one Docker container.

The gate keeps remote and shell access **closed by default**. When you need
it, you open a window for as long as you choose from a phone friendly page.
While the window is open the gate reminds you; when it ends, the gate warns
you and then closes everything again by itself.

It is the NAS counterpart of the
[Home Assistant agent gate](https://github.com/yaniv376/ha-agent-gate) and is
built to suit any Synology user, not one particular setup.

## What stage 1 does

| Protection | Closed | Open |
|---|---|---|
| QuickConnect | disabled in DSM | enabled |
| SSH | reachable only from your trusted hosts (for example the Home Assistant machine that pulls backups) | reachable from anywhere |

Plus:

* one personal password for the page, auto lock after idle time, manual lock button
* reminders while open, warning before auto close, closing report, all to your phone (Home Assistant or any webhook)
* every protection has its own on/off switch, so you can leave one unmanaged
* an API token so Home Assistant can show the state and open or close the gate (stage 2 adds a ready made dashboard card)
* Hebrew and English UI

## Requirements

* DSM 7 with Container Manager (or Portainer)
* A dedicated DSM user for the gate, in the **administrators** group, with
  2 step verification **off** for that user (the DSM API cannot answer an
  OTP prompt). Give it a long random password. It is only ever used from
  inside the NAS.
* SSH enabled in DSM (Control Panel → Terminal & SNMP). The gate controls
  *who* can reach the port; it does not turn SSH itself off.

## Install (Container Manager)

1. Create the folder `docker/nas-gate` on your volume (for example
   `/volume1/docker/nas-gate`).
2. In Container Manager → Project → Create, paste `docker-compose.yml` from
   this repo (adjust the volume path if needed) and build the project.
3. Open `http://<nas-ip>:8787` and choose the gate password.
4. In Settings on that page:
   * **DSM connection**: user and password of the gate's DSM user, then
     *Test DSM connection*.
   * **SSH**: add the trusted hosts that must always reach SSH, one IP or
     CIDR per entry (your Home Assistant machine, maybe your LAN).
   * **Notifications**: Home Assistant URL, a long lived access token and
     the notify service for your phone, then *Send test notification*.
5. Save. The gate is now closed. Tap *Open gate* when you need access.

The container needs `network_mode: host` and `cap_add: NET_ADMIN`: it reaches
DSM on 127.0.0.1 and manages the host's SSH port with its own small
iptables chain (`NASGATE`). Nothing else on the NAS is touched.

## How the SSH rule works

```
INPUT  -> NASGATE
NASGATE: -s <trusted host> -p tcp --dport 22 -j RETURN   (one per host)
         -p tcp --dport 22 -j DROP
```

While open the chain is empty. Rules live in the host kernel, so a container
restart does not change your exposure; the gate re-applies its position on
every start. If DSM's own firewall is enabled and re-applied it may drop the
jump rule, which fails *open* (SSH reachable), never locks you out.

If the gate itself is unreachable you can always remove the rules from an
SSH session on the NAS or from DSM's Task Scheduler:

```
iptables -D INPUT -j NASGATE; iptables -F NASGATE; iptables -X NASGATE
```

## Home Assistant integration (manual, stage 1)

The page shows an API token under *Settings → Home Assistant integration*.

```yaml
rest:
  - resource: http://<nas-ip>:8787/api/status
    headers:
      Authorization: "Bearer <api token>"
    scan_interval: 30
    binary_sensor:
      - name: NAS gate open
        value_template: "{{ value_json.is_open }}"
    sensor:
      - name: NAS gate remaining
        value_template: "{{ (value_json.remaining_seconds / 60) | round(0) }}"
        unit_of_measurement: min

rest_command:
  nas_gate_open:
    url: http://<nas-ip>:8787/api/open?minutes=60
    method: POST
    headers:
      Authorization: "Bearer <api token>"
  nas_gate_close:
    url: http://<nas-ip>:8787/api/close
    method: POST
    headers:
      Authorization: "Bearer <api token>"
```

## Updating

Pull the new image in Container Manager and rebuild the project. Settings
and state live in `/data` and are kept.

## Roadmap

1. ✅ Gate core, QuickConnect, SSH, page, notifications
2. Home Assistant dashboard card and optional one tap link from the HA gate
3. Security scan with a report and one click suggestions
4. Sharing polish, documentation, example configs
5. Optional native Synology package

## Development

```
pip install -r requirements.txt pytest
python -m pytest -q
NASGATE_DATA_DIR=./data python -m nasgate.main
```

## License

MIT
