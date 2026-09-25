#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against stub Flask /
flask_login modules so nothing here needs Jen, a database, nmap, or a
browser; every check exercises a PURE function of the plugin
(classification precedence, MAC-keyed deltas and new-unknowns, the
nmap / neighbour-table parsers, scope and timeout rules, scheduling).

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import ipaddress
import os
import sys
import types
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", role="superadmin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_jen_plugin_api():
    """A stub `jen.plugin_api` sufficient for register(app) to run end to end, enforcing the SAME two
    rules Jen's real one does: an alert type id must start with '<plugin_id>_', and a periodic job may
    not run more often than PERIODIC_MIN_MINUTES (5). Watchdog and DNS Sync shipped unable to load
    because a plugin's own register() broke one of them and nothing ever called it (Q89); this
    harness predates that lesson. Note register() here wraps register_periodic in a try/except, so a
    violation would be SWALLOWED and the scheduled scans silently absent — hence the check below
    that the call actually landed. Returns the registered calls."""
    calls = {"alert_types": [], "periodic": [], "search": []}

    def register_alert_type(plugin_id, type_id, **kwargs):
        prefix = f"{plugin_id}_"
        if not type_id.startswith(prefix):
            raise ValueError(f"type_id {type_id!r} must start with {prefix!r}")
        calls["alert_types"].append(type_id)

    def register_periodic(plugin_id, name, fn, every_minutes):
        if every_minutes < 5:
            raise ValueError("every_minutes must be at least 5")
        calls["periodic"].append((plugin_id, name, every_minutes))

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_alert_type = register_alert_type
    plugin_api.register_periodic = register_periodic
    plugin_api.register_search_provider = lambda *a, **k: calls["search"].append(a)
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return calls


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("nd_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()
    # No Jen here: the OUI lookup returns blanks.
    p._vendor = lambda mac, hostname: ("", "", "")

    # ── classification precedence ────────────────────────────────────────────
    found = [
        {"ip": "10.0.0.1", "mac": "", "hostname": ""},  # gateway
        {"ip": "10.0.0.2", "mac": "aa:aa:aa:aa:aa:02", "hostname": ""},  # jen host
        {"ip": "10.0.0.20", "mac": "aa:aa:aa:aa:aa:20", "hostname": "laptop"},  # lease by ip
        {"ip": "10.0.0.21", "mac": "aa:aa:aa:aa:aa:21", "hostname": ""},  # lease by mac (ip hopped)
        {"ip": "10.0.0.30", "mac": "aa:aa:aa:aa:aa:30", "hostname": ""},  # global reservation by mac
        {"ip": "10.0.0.40", "mac": "", "hostname": "nas"},  # ipam by ip
        {"ip": "10.0.0.41", "mac": "aa:aa:aa:aa:aa:41", "hostname": ""},  # ipam by mac
        {"ip": "10.0.0.50", "mac": "aa:aa:aa:aa:aa:50", "hostname": ""},  # devices table, no lease
        {"ip": "10.0.0.60", "mac": "aa:aa:aa:aa:aa:60", "hostname": ""},  # marked known by mac
        {"ip": "10.0.0.61", "mac": "", "hostname": ""},  # marked known by ip
        {"ip": "10.0.0.99", "mac": "aa:aa:aa:aa:aa:99", "hostname": "mystery"},  # unknown
        {"ip": "10.0.0.98", "mac": "", "hostname": ""},  # unknown, no mac
    ]
    kea = ({"10.0.0.20"}, {"aa:aa:aa:aa:aa:21"}, set(), {"aa:aa:aa:aa:aa:30"})
    ctx = {
        "infrastructure": {
            "10.0.0.1": "gateway",
            "10.0.0.2": "jen-host",
            "10.0.0.0": "network",
            "10.0.0.255": "broadcast",
        }
    }
    ipam = ({"10.0.0.40": "NAS"}, {"aa:aa:aa:aa:aa:41": "Camera"})
    devices = {
        "aa:aa:aa:aa:aa:50": {
            "name": "Printer",
            "owner": "",
            "manufacturer": "HP",
            "device_type": "printer",
            "icon": "🖨",
        }
    }
    known = {("aa:aa:aa:aa:aa:60", ""): "lab switch", ("", "10.0.0.61"): "console server"}
    out = p.classify(found, kea, ctx, ipam, devices, known)
    by = {h["ip"]: h for h in out}
    exp = {
        "10.0.0.1": ("infrastructure", "Gateway"),
        "10.0.0.2": ("infrastructure", "Jen host"),
        "10.0.0.20": ("lease", ""),
        "10.0.0.21": ("lease", ""),
        "10.0.0.30": ("reservation", ""),
        "10.0.0.40": ("ipam", "NAS"),
        "10.0.0.41": ("ipam", "Camera"),
        "10.0.0.50": ("device", "Printer"),
        "10.0.0.60": ("known", "lab switch"),
        "10.0.0.61": ("known", "console server"),
        "10.0.0.99": ("unknown", ""),
        "10.0.0.98": ("unknown", ""),
    }
    for ip, (status, label) in exp.items():
        check(by[ip]["status"] == status and by[ip]["label"] == label, f"{ip} → {status} {label!r}")
    check(by["10.0.0.50"]["vendor"] == "HP" and by["10.0.0.50"]["icon"] == "🖨", "devices table supplies vendor/icon")
    check(by["10.0.0.20"]["in_kea"] and not by["10.0.0.20"]["rogue"], "in_kea/rogue derived for a lease")
    check(not by["10.0.0.99"]["in_kea"] and by["10.0.0.99"]["rogue"], "rogue means unknown")
    check(not by["10.0.0.60"]["rogue"], "a known host is not rogue")
    check(sum(1 for h in out if h["status"] == "unknown") == 2, "exactly the two mysteries are unknown")

    # precedence: a lease beats infrastructure and ipam even when both match
    both = p.classify([{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:21", "hostname": ""}], kea, ctx, ipam, devices, known)
    check(both[0]["status"] == "lease", "lease wins over infrastructure")
    infra_vs_ipam = p.classify(
        [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:41", "hostname": ""}],
        (set(), set(), set(), set()),
        ctx,
        ipam,
        devices,
        known,
    )
    check(infra_vs_ipam[0]["status"] == "infrastructure", "infrastructure wins over ipam")
    dev_vs_known = p.classify(
        [{"ip": "10.0.0.7", "mac": "aa:aa:aa:aa:aa:50", "hostname": ""}],
        (set(), set(), set(), set()),
        ctx,
        ({}, {}),
        devices,
        {("aa:aa:aa:aa:aa:50", ""): "x"},
    )
    check(dev_vs_known[0]["status"] == "device", "device wins over known")

    # ── MAC-keyed deltas and new unknowns ────────────────────────────────────
    prev = [
        {"ip": "10.0.0.99", "mac": "aa:aa:aa:aa:aa:99", "status": "unknown"},
        {"ip": "10.0.0.98", "mac": "", "status": "unknown"},
        {"ip": "10.0.0.20", "mac": "aa:aa:aa:aa:aa:20", "status": "lease"},
    ]
    prev_keys = {p.host_key(r) for r in prev if r["status"] == "unknown"}
    cur = [
        {"ip": "10.0.0.77", "mac": "aa:aa:aa:aa:aa:99", "status": "unknown"},  # same MAC, hopped IP
        {"ip": "10.0.0.98", "mac": "", "status": "unknown"},  # same IP, no MAC
        {"ip": "10.0.0.66", "mac": "aa:aa:aa:aa:aa:66", "status": "unknown"},  # genuinely new
        {"ip": "10.0.0.20", "mac": "aa:aa:aa:aa:aa:20", "status": "lease"},
    ]
    fresh = p.new_unknowns(cur, prev_keys)
    check([h["ip"] for h in fresh] == ["10.0.0.66"], "an IP hop is not a new unknown; a new MAC is")
    check(len(p.new_unknowns(cur, None)) == 3, "with no previous scan every unknown is new")
    appeared, gone = p.delta(cur, prev)
    check([h["ip"] for h in appeared] == ["10.0.0.66"] and gone == [], "delta keyed by MAC: only the new host appeared")
    appeared, gone = p.delta(cur[1:], prev)
    check([h["ip"] for h in gone] == ["10.0.0.99"], "a MAC that vanished is gone even though its old IP is unlisted")

    # ── parsers (unchanged from v1.0.3, still guarded) ───────────────────────
    net = ipaddress.IPv4Network("10.0.0.0/24")
    hosts = p._parse_nmap_greppable(
        "# Nmap\nHost: 10.0.0.5 (printer.lan)\tStatus: Up\nHost: 10.0.0.6 ()\tStatus: Up\nHost: bad\n"
    )
    check(
        [(h["ip"], h["hostname"]) for h in hosts] == [("10.0.0.5", "printer.lan"), ("10.0.0.6", "")],
        "nmap greppable parse",
    )
    neigh = p._parse_neighbours(
        "10.0.0.6 dev eth0 lladdr aa:bb:cc:dd:ee:06 REACHABLE\n10.0.0.7 dev eth0 lladdr AA:BB:CC:DD:EE:07 STALE\n10.0.0.8 dev eth0 FAILED\n10.9.9.9 dev eth0 lladdr 00:00:00:00:00:09 REACHABLE\n",
        net,
    )
    check(
        neigh == {"10.0.0.6": ("aa:bb:cc:dd:ee:06", "REACHABLE"), "10.0.0.7": ("aa:bb:cc:dd:ee:07", "STALE")},
        "neighbour parse: dead/outside dropped, MAC lowercased",
    )
    merged = p._merge_neighbours(hosts, neigh)
    check(
        [(h["ip"], h["mac"]) for h in merged] == [("10.0.0.5", ""), ("10.0.0.6", "aa:bb:cc:dd:ee:06")],
        "STALE alone adds no host; REACHABLE supplies the MAC",
    )

    # ── scope and timeout ────────────────────────────────────────────────────
    check(
        p.scan_scope_error("10.0.0.0/24") is None and p.scan_scope_error("10.0.0.0/20") is None, "/24 and /20 in scope"
    )
    check("larger than a /20" in (p.scan_scope_error("10.0.0.0/16") or ""), "/16 refused with a reason")
    check("Invalid" in (p.scan_scope_error("nonsense") or ""), "bad CIDR refused")
    check(p.scan_timeout_for(ipaddress.IPv4Network("10.0.0.0/24")) == 92, "a /24 gets 92 s")
    check(p.scan_timeout_for(ipaddress.IPv4Network("10.0.0.0/20")) == 572, "a /20 gets 572 s")
    check(p.scan_timeout_for(ipaddress.IPv4Network("10.0.0.0/16")) == 900, "the cap holds")

    # ── scheduling ───────────────────────────────────────────────────────────
    now = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)
    schedules = {1: 6, 2: 24, 3: 6, 4: 6}
    last_done = {1: now - timedelta(hours=7), 2: now - timedelta(hours=1), 3: now - timedelta(hours=5)}
    due = p.due_subnets(schedules, last_done, running={4}, now=now)
    check(
        sorted(due) == [1],
        "due: overdue yes, recent no, not-yet no, running excluded, never-run (4) excluded only because running",
    )
    check(p.due_subnets({5: 12}, {}, set(), now) == [5], "a scheduled subnet that never ran is due")
    check(p.due_subnets({}, {}, set(), now) == [], "no schedules, nothing due")
    # v1.1.2 — _scheduled_tick() now puts a subnet's id in `running` whether
    # its latest job row is 'running' OR 'queued'; due_subnets() itself just
    # treats `running` as an opaque exclusion set, so a queued id excludes
    # the same way an actually-running one always did.
    check(p.due_subnets({6: 6}, {}, running={6}, now=now) == [], "a queued id in the running set is excluded from due")

    # ── csv guard fallback ───────────────────────────────────────────────────
    check(p._safe_row(["=1+1", "ok", None]) == ["'=1+1", "ok", ""], "CSV formula guard (local fallback)")

    # ── write gate (v1.1.2) — viewers can look at Discovery but not scan or mark hosts ─
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    # request is None in this harness; a route that reaches request.form
    # raises AttributeError, so returning None without raising proves
    # _require_write() stopped it first.
    for fn, args in (
        (p.start_scan, (1,)),
        (p.mark_known, (1,)),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "superadmin"
    check(p._is_admin() is True, "superadmin role restored for the rest of the run")

    # ── register(): runs end to end against a stub that enforces Jen's rules ──
    calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    check(
        calls["alert_types"] == [p._ROGUE_ALERT_TYPE],
        f"register(): the rogue-device alert type is registered under the plugin's own prefix (got {calls['alert_types']})",
    )
    check(
        calls["periodic"] == [("network-discovery", "scheduled-scans", p._SCHEDULE_TICK_MINUTES)],
        f"register(): the scheduled-scan tick actually registered — its failure is swallowed, so absence is silent (got {calls['periodic']})",
    )
    check(len(calls["search"]) == 1, "register(): one search provider")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
