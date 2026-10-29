# NAS Gate

An open/close security gate for a Synology NAS, in one Docker container.

The gate keeps remote and shell access **closed by default**. When you need
it, you open a window for as long as you choose from a phone friendly page.
Every protection has its own window and timer: open only SSH for 30 minutes,
or only QuickConnect for the evening, or everything at once. While a window
is open the gate reminds you; when it ends, the gate warns you and then closes
that protection again by itself.

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
* every protection has its own window and timer (open, extend and close one at a time, or *Open everything*)
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

## Home Assistant integration

The page shows an API token under *Settings → Home Assistant integration*.
Paste it into a **Text helper** (mode *password*) named `NAS Gate token`
in Home Assistant, then install the package and scripts from
[`examples/homeassistant/`](examples/homeassistant/):

* `nas_gate.yaml` — REST sensors (`binary_sensor.nas_gate`, one
  `binary_sensor.nas_gate_<protection>` per protection, remaining minutes
  for each, `sensor.nas_gate_status`) and the
  `rest_command.nas_gate_open / extend / close` commands. Each command takes
  `protections`: `all` (default), `ssh`, `quickconnect`, or a comma list.
* `scripts_and_automation.yaml` — three scripts for dashboard buttons, and
  the automation that makes the phone notification's **+1 hour** and
  **Close now** buttons work. When everything was opened together the gate
  sends the generic actions `NAS_GATE_EXTEND_60` / `NAS_GATE_CLOSE`; for a
  single protection it appends its id (`NAS_GATE_CLOSE_SSH`), so the button
  touches only that window.

API: `POST /api/open?minutes=30&protections=ssh`, `POST /api/extend?minutes=60&protections=ssh`,
`POST /api/close?protections=ssh`. Leave `protections` out for every managed protection.
`GET /api/status` lists each protection with `is_open`, `expires_at` and `remaining_seconds`.

A dashboard card example follows the same pattern as the Home Assistant
agent gate: status, four duration buttons, extend, close.

## Security scan

The *Scan now* button on the page checks the NAS and lists findings with a
severity, a plain-language explanation and, where it cannot lock you out, a
*Fix* button (telnet off, auto block on, HTTPS redirect, HSTS, SMB minimum
SMB2). Checks: DSM updates, Telnet/SSH, auto block, DSM firewall, HTTPS
redirect and HSTS, SMB1, the default `admin` and `guest` accounts, 2 step
verification enforcement, QuickConnect versus the gate state, DSM Security
Advisor results, and every service listening on all network interfaces. The
score and counts are also exposed in `/api/status` (`scan`) for Home
Assistant.

## Updating

The page has an *Updates* card: *Check for updates* compares the running
build with the newest image in the registry, and *Update now* asks your
**Watchtower** container to pull it and recreate the gate (a restart of
about a minute; settings and state live in `/data` and are kept).

Watchtower setup, once (in its compose):

```yaml
services:
  watchtower:
    image: containrrr/watchtower
    environment:
      WATCHTOWER_HTTP_API_UPDATE: "true"
      WATCHTOWER_HTTP_API_TOKEN: "choose-a-long-random-token"
      WATCHTOWER_HTTP_API_PERIODIC_POLLS: "true"   # keep its normal schedule too
    ports:
      - "8085:8080"
```

Then put the same token under *Settings → Updates* on the gate page
(Watchtower address defaults to `http://127.0.0.1:8085`). Without Watchtower,
update by hand: Container Manager → Project → stop and clean the project,
delete the image, build again.

## Roadmap

1. ✅ Gate core, QuickConnect, SSH, page, notifications
2. ✅ Home Assistant integration (package, scripts, notification buttons)
3. ✅ Security scan with a report and one click fixes
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
