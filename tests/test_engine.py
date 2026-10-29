import os
import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NASGATE_DATA_DIR", str(tmp_path))
    import importlib
    from nasgate import config, state, engine
    importlib.reload(config); importlib.reload(state); importlib.reload(engine)
    return config, state, engine


class FakeController:
    def __init__(self, cid, fail=False):
        self.id = cid; self.calls = []; self.fail = fail
    def apply(self, open_):
        self.calls.append(open_)
        if self.fail:
            raise RuntimeError("boom")
    def status(self):
        from nasgate.controllers import ControllerStatus
        return ControllerStatus(self.id, "open" if (self.calls and self.calls[-1]) else "closed")


def make(env, now=[1000.0], fail_ssh=False):
    config, state, engine = env
    s = config.load(); s.language = "en"; s.reminder_minutes = 60; s.guard_grace_minutes = 5; s.password_hash = "x$y"
    sent = []
    qc, ssh = FakeController("quickconnect"), FakeController("ssh", fail=fail_ssh)
    eng = engine.GateEngine(s, state.GateState(), {"quickconnect": qc, "ssh": ssh},
                            clock=lambda: now[0], notifier=lambda s, t, m, e: sent.append((e, t, m)))
    return eng, qc, ssh, sent, now


def test_open_close_applies_controllers(env):
    eng, qc, ssh, sent, now = make(env)
    assert eng.open(60) == []
    assert qc.calls == [True] and ssh.calls == [True]
    assert eng.state.is_open and eng.state.remaining_seconds(now[0]) == 3600
    assert sent[0][0] == "n_opened"
    assert eng.close() == []
    assert qc.calls[-1] is False and not eng.state.is_open
    assert sent[-1][0] == "n_closed"


def test_reminder_then_warning_then_close(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(90)
    now[0] += 61 * 60; eng.tick()
    assert sent[-1][0] == "n_reminder"
    now[0] += 30 * 60; eng.tick()            # expired -> warning only
    assert sent[-1][0] == "n_warning" and eng.state.is_open
    now[0] += 2 * 60; eng.tick()             # still inside grace
    assert eng.state.is_open
    now[0] += 4 * 60; eng.tick()             # grace over -> closed
    assert not eng.state.is_open and eng.state.last_close_reason == "expired"


def test_extend_cancels_guard(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(10)
    now[0] += 11 * 60; eng.tick()
    assert sent[-1][0] == "n_warning"
    eng.extend(30)
    now[0] += 6 * 60; eng.tick()
    assert eng.state.is_open and eng.state.guard_warned_at == 0


def test_controller_error_is_reported_not_fatal(env):
    eng, qc, ssh, sent, now = make(env, fail_ssh=True)
    errors = eng.open(5)
    assert errors and "ssh" in errors[0]
    assert qc.calls == [True] and eng.state.is_open
    assert eng.state.applied["ssh"].startswith("error")
    assert sent[-1][0] == "n_error"


def test_unmanaged_controller_is_skipped(env):
    eng, qc, ssh, sent, now = make(env)
    eng.set_managed("ssh", False)
    assert ssh.calls == [True]              # released
    eng.open(5)
    assert ssh.calls == [True] and qc.calls == [True]


def test_startup_closes_expired_window(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(5)
    now[0] += 10 * 60
    eng.startup()
    assert not eng.state.is_open and eng.state.last_close_reason == "startup"


def test_state_persists(env):
    config, state, engine = env
    eng, *_ = make(env)
    eng.open(5)
    assert state.load().is_open


def test_startup_is_noop_before_setup(env):
    eng, qc, ssh, sent, now = make(env)
    eng.settings.password_hash = ""
    eng.startup(); eng.tick()
    assert qc.calls == [] and ssh.calls == []
    eng.settings.password_hash = "x$y"
    eng.startup()
    assert qc.calls == [False] and ssh.calls == [False]


# -- per-protection windows ---------------------------------------------------------

def test_open_one_protection_only(env):
    eng, qc, ssh, sent, now = make(env)
    assert eng.open(30, ["ssh"]) == []
    assert ssh.calls == [True] and qc.calls == []
    assert eng.state.window_open("ssh") and not eng.state.window_open("quickconnect")
    assert eng.state.is_open and eng.state.remaining_seconds(now[0]) == 1800
    assert sent[-1][0] == "n_opened:ssh" and "SSH" in sent[-1][1]


def test_independent_timers(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(10, ["ssh"])
    eng.open(60, ["quickconnect"])
    now[0] += 11 * 60; eng.tick()                 # ssh expired -> warning for ssh only
    assert sent[-1][0] == "n_warning:ssh"
    now[0] += 6 * 60; eng.tick()                  # grace over -> ssh closed, qc still open
    assert not eng.state.window_open("ssh") and eng.state.window_open("quickconnect")
    assert ssh.calls[-1] is False and qc.calls[-1] is True
    assert eng.state.is_open and sent[-1][0] == "n_closed:ssh"


def test_close_one_keeps_other(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(60)
    assert eng.close("manual", ["ssh"]) == []
    assert ssh.calls[-1] is False and qc.calls[-1] is True
    assert eng.state.is_open and eng.state.open_ids() == ["quickconnect"]


def test_extend_only_open_windows(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(10, ["ssh"])
    eng.extend(30)                                # default: every open window
    assert eng.state.window_remaining("ssh", now[0]) == 40 * 60
    assert not eng.state.window_open("quickconnect")
    with pytest.raises(ValueError):
        eng.extend(5, ["quickconnect"])


def test_grouped_notifications_when_opened_together(env):
    eng, qc, ssh, sent, now = make(env)
    eng.open(90)
    assert sent[-1][0] == "n_opened"              # generic buttons for "everything"
    now[0] += 61 * 60; eng.tick()
    assert [e for e, *_ in sent].count("n_reminder") == 1


def test_state_migration_from_single_window(env):
    config, state, engine = env
    import json
    state.DATA_DIR.mkdir(parents=True, exist_ok=True)
    state.STATE_FILE.write_text(json.dumps({"is_open": True, "opened_at": 100.0, "expires_at": 5000.0,
                                            "applied": {"ssh": "open", "quickconnect": "open"}}))
    loaded = state.load()
    assert loaded.windows["ssh"]["expires_at"] == 5000.0 and loaded.is_open
