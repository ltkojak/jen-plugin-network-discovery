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
    calls = {"alert_types": [], "periodic": [], "search": [], "investigation": [], "subnets": {1, 2, 9}}

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
    plugin_api.register_investigation_provider = lambda *a, **k: calls["investigation"].append((a, k))
    plugin_api.assert_subnet_access = lambda subnet_id: True
    plugin_api.ACTIVE_LEASE4 = "state = 0 AND expire > NOW()"

    def normalize_mac(raw):
        import re as _re

        if not isinstance(raw, str) or not raw.strip():
            return None
        cleaned = _re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        if len(cleaned) != 12:
            return None
        mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
        return mac if _re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) else None

    def like_pattern(text):
        return "%" + str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def in_placeholders(values):
        n = len(list(values))
        return ",".join(["%s"] * n) if n else "NULL"

    def search_scope(accessible_ids, all_subnets, column):
        if all_subnets:
            return "1=1", []
        ids = sorted({int(i) for i in (accessible_ids or [])})
        if not ids:
            return None
        return f"{column} IN ({in_placeholders(ids)})", ids

    def subnet_or_404(subnet_id):
        return ({"name": "n"}, None) if subnet_id in calls["subnets"] else (None, ({"error": "not found"}, 404))

    plugin_api.normalize_mac = normalize_mac
    plugin_api.like_pattern = like_pattern
    plugin_api.in_placeholders = in_placeholders
    plugin_api.search_scope = search_scope
    plugin_api.subnet_or_404 = subnet_or_404
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

    _stub_jen_plugin_api()  # the routes below import assert_subnet_access from it

    # ── 1.2.2: pruning never deletes the newest completed scan ───────────────
    def _simulate(statuses):
        """Run scans with these outcomes in order (only a completed one prunes, as in the plugin);
        returns the jobs left, newest first, and whether a completed baseline existed at each finish."""
        jobs, baselines = [], []
        for jid, status in enumerate(statuses):
            others = list(jobs)
            baselines.append(any(j["status"] == "done" for j in others))
            gone = set(p.jobs_to_prune(others, p._KEEP_JOBS)) if status == "done" else set()
            jobs = [{"id": jid, "status": status}] + [j for j in others if j["id"] not in gone]
        return jobs, baselines

    left, baselines = _simulate(["done", "error", "error", "done", "done"])
    check(
        baselines[-1] and left[0]["status"] == "done",
        "prune: done, error, error, done, done keeps a baseline throughout",
    )
    check(
        p.jobs_to_prune([{"id": 6, "status": "error"}, {"id": 5, "status": "error"}, {"id": 4, "status": "done"}], 3)
        == [],
        "jobs_to_prune: the newest done job survives two newer failures",
    )
    check(
        p.jobs_to_prune(
            [
                {"id": 9, "status": "done"},
                {"id": 8, "status": "error"},
                {"id": 7, "status": "error"},
                {"id": 6, "status": "done"},
            ],
            3,
        )
        == [7, 6],
        "jobs_to_prune: everything older than the window and the newest done goes",
    )
    check(
        p.jobs_to_prune([{"id": 5, "status": "done"}, {"id": 4, "status": "done"}, {"id": 3, "status": "queued"}], 2)
        == [4],
        "jobs_to_prune: a queued job is never pruned (its thread will still write to it)",
    )
    check(p.jobs_to_prune([], 3) == [], "jobs_to_prune: nothing to prune")

    class FakeDB:
        """Records every statement; answers from `script` (a function of the last SQL and params)."""

        def __init__(self, answer=None, fail_on=None):
            self.log, self.answer, self.fail_on = [], answer or (lambda sql, params: None), fail_on
            self.sql, self.params, self.lastrowid = "", (), 1

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.sql, self.params = " ".join(sql.split()), params
            self.log.append((self.sql, params))
            if self.fail_on and self.fail_on in self.sql:
                raise RuntimeError("boom-marker")

        def fetchone(self):
            r = self.answer(self.sql, self.params)
            return r[0] if isinstance(r, list) and r else (None if isinstance(r, list) else r)

        def fetchall(self):
            r = self.answer(self.sql, self.params)
            return r if isinstance(r, list) else ([r] if r else [])

        def commit(self):
            self.log.append(("COMMIT", ()))

        def rollback(self):
            self.log.append(("ROLLBACK", ()))

        def close(self):
            pass

    # ── 1.2.2: a scan run end to end against a fake database ─────────────────
    ctx_full = {"gateways": [], "dns": [], "pools": [], "infrastructure": {}, "notes": ""}
    long_name = "h" * 300
    p._scan_subnet = lambda cidr: {"hosts": [{"ip": "10.0.0.5", "mac": "", "hostname": long_name}]}
    p._subnet_ctx = lambda sid, cidr: ctx_full
    p._load_kea = lambda sid: (set(), set(), set(), set())
    p._load_ipam = lambda sid: ({}, {})
    p._load_devices = lambda macs: {}
    p._load_known = dict
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._run_scan_job(1, "10.0.0.0/24", 7)
    inserts = [prm for sql, prm in fdb.log if sql.startswith("INSERT INTO nd_scan_results")]
    check(
        len(inserts) == 1 and len(inserts[0][3]) == 255,
        "scan: a 300-character hostname is truncated to the column's 255",
    )
    check(
        any("UPDATE nd_scan_jobs SET status=%s" in sql and prm[0] == "done" for sql, prm in fdb.log),
        "scan: a run whose insert succeeds is marked done",
    )
    fdb = FakeDB(fail_on="INSERT INTO nd_scan_results")
    p._get_db = lambda: fdb
    p._run_scan_job(1, "10.0.0.0/24", 8)
    verbs = [sql.split()[0] for sql, _p in fdb.log]
    marked = [
        i for i, (sql, prm) in enumerate(fdb.log) if "UPDATE nd_scan_jobs SET status=%s" in sql and prm[0] == "error"
    ]
    check(
        marked and "ROLLBACK" in verbs and verbs.index("ROLLBACK") < marked[0],
        "scan: a run that fails after staging its prune rolls back BEFORE it records the error (the prune is not committed)",
    )

    # ── 1.2.2: a queued job is not expired while its thread is alive ──────────
    class StaleCursor:
        def __init__(self):
            self.log = []

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split())
            self.log.append((self.last, params))

        def fetchall(self):
            return (
                [{"id": 11}, {"id": 12}]
                if self.last.startswith("SELECT id FROM nd_scan_jobs WHERE status='queued'")
                else []
            )

    p._live_jobs.clear()
    p._live_jobs.add(11)
    sc = StaleCursor()
    p._expire_stale_running_jobs(sc)
    expired = [prm for sql, prm in sc.log if sql.startswith("UPDATE") and "WHERE id=%s AND status='queued'" in sql]
    check(
        expired == [(12,)],
        f"expiry: an old queued job whose thread is alive stays queued; a leftover expires (got {expired})",
    )
    check(
        any("status='running' AND started_at <" in sql for sql, _p in sc.log),
        "expiry: a running job past the window still expires by age",
    )
    p._live_jobs.clear()

    # ── 1.2.2: the results page shows the latest COMPLETED scan ──────────────
    def results_answer(sql, params):
        if "FROM nd_scan_results WHERE job_id=%s" in sql or "FROM nd_scan_results WHERE job_id" in sql:
            row = {
                "ip": "10.0.0.5",
                "mac": "aa:aa:aa:aa:aa:05",
                "hostname": "h",
                "in_kea": 1,
                "rogue": 0,
                "status": "lease",
                "label": "",
                "vendor": "",
                "device_type": "",
                "discovered_at": None,
            }
            return [dict(row)]
        if "AND id != %s AND status='done'" in sql:
            return {"id": 2}
        if "status='done'" in sql:
            return {
                "id": 3,
                "status": "done",
                "started_at": None,
                "finished_at": None,
                "hosts_found": 1,
                "rogue_count": 0,
                "error": None,
            }
        return {
            "id": 4,
            "status": "error",
            "started_at": None,
            "finished_at": None,
            "hosts_found": 0,
            "rogue_count": 0,
            "error": "timed out",
        }

    p._subnet_map = lambda: {1: {"name": "n", "cidr": "10.0.0.0/24"}}
    p.render_template = lambda name, **kw: kw
    p.url_for = lambda *a, **k: "/x"
    p.redirect = lambda where: ("redirect", where)
    p.flash = lambda *a, **k: None
    p._get_db = lambda: FakeDB(results_answer)
    page = p.results(1)
    check(
        page["job"]["id"] == 3 and page["newer_job"]["id"] == 4 and len(page["hosts"]) == 1,
        "results: the latest done scan is shown, with the newer failed one named for the banner",
    )
    check(
        page["gone"] == [] and page["appeared"] == [], "results: a failed newest scan does not list every host as gone"
    )

    def only_error(sql, params):
        if "FROM nd_scan_results" in sql or "status='done'" in sql:
            return []
        return {
            "id": 4,
            "status": "error",
            "started_at": None,
            "finished_at": None,
            "hosts_found": 0,
            "rogue_count": 0,
            "error": "x",
        }

    p._get_db = lambda: FakeDB(only_error)
    page = p.results(1)
    check(
        page["job"]["id"] == 4 and page["newer_job"] is None and page["hosts"] == [],
        "results: with no completed scan the failed one is shown as before",
    )

    # ── 1.2.2: the known-hosts list is an all-subnets object ─────────────────
    _stub_jen_plugin_api()
    for role, all_subnets, expect in (
        ("admin", False, False),
        ("admin", True, True),
        ("viewer", True, False),
        ("superadmin", True, True),
    ):
        p.current_user.role, p.current_user.all_subnets = role, all_subnets
        check(
            p._can_change_known() is expect, f"_can_change_known: a {role} with all_subnets={all_subnets} -> {expect}"
        )
    flashed = []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.current_user.role, p.current_user.all_subnets = "admin", False
    p.request = types.SimpleNamespace(form={"ip": "10.0.0.99", "mac": "", "note": "x"})
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p.mark_known(1)
    check(fdb.log == [] and flashed, "mark_known: a subnet-scoped admin is refused and nothing is written")
    p.current_user.all_subnets = True
    flashed.clear()
    p.mark_known(1)
    check(
        any(sql.startswith("INSERT INTO nd_known_hosts") for sql, _p in fdb.log),
        "mark_known: an admin who sees every subnet can mark a host",
    )
    for bad in ("aaaaaaaaaaaaaaaaa", "aa:bb", "zz:zz:zz:zz:zz:zz", "aa:aa:aa:aa:aa:aa:aa"):
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(form={"ip": "", "mac": bad, "note": ""})
        p.mark_known(1)
        check(
            fdb.log == [], f"mark_known: {bad!r} is not a MAC (the old check accepted any 17 characters of [0-9a-f:])"
        )
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(form={"ip": "", "mac": "AA:BB:CC:DD:EE:FF", "note": ""})
    p.mark_known(1)
    check(
        any(sql.startswith("INSERT INTO nd_known_hosts") and prm[0] == "aa:bb:cc:dd:ee:ff" for sql, prm in fdb.log),
        "mark_known: an upper-case MAC is accepted and stored lower-case",
    )
    p.current_user.role, p.current_user.all_subnets = "superadmin", True

    # ── 1.2.2: search looks at the latest completed scan only ────────────────
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._discovery_search("a_b%", {1}, True)
    sql, prm = fdb.log[0]
    check("j2.status = 'done'" in sql and "LIMIT 1" in sql, "search: restricted to each subnet's latest completed scan")
    check(prm[0] == "%a\\_b\\%%", f"search: % and _ are literal (got {prm[0]!r})")

    # ── 1.2.3 (Q100): the search provider scopes in SQL, before its own LIMIT ──
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._discovery_search("printer", {1}, False)
    sql, prm = fdb.log[0]
    check(
        "j.subnet_id IN (%s)" in sql and prm[0] == 1,
        f"search: a restricted caller's own subnet scope is in the SQL, not applied afterward (got {sql!r}, {prm})",
    )
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._discovery_search("printer", set(), False)
    check(fdb.log == [], "search: a caller who may see nothing runs no query at all")

    # ── 1.2.3 (Q100 a): known/unknown is derived at READ time, everywhere ────
    known_now = {("aa:aa:aa:aa:aa:01", ""): "printer"}
    stored_unknown = {"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:01", "status": "unknown", "rogue": True, "label": ""}
    stored_known_but_forgotten = {
        "ip": "10.0.0.6",
        "mac": "aa:aa:aa:aa:aa:02",
        "status": "known",
        "rogue": False,
        "label": "old note",
    }
    stored_lease = {"ip": "10.0.0.7", "mac": "", "status": "lease", "rogue": False, "label": ""}
    out = p.apply_known([dict(stored_unknown), dict(stored_known_but_forgotten), dict(stored_lease)], known_now)
    check(
        out[0]["status"] == "known" and out[0]["rogue"] is False and out[0]["label"] == "printer",
        "apply_known: a host marked known elsewhere reads known here too, without a rescan",
    )
    check(
        out[1]["status"] == "unknown" and out[1]["rogue"] is True,
        "apply_known: a host forgotten elsewhere reads unknown here too, without a rescan",
    )
    check(out[2]["status"] == "lease", "apply_known: a status the known list has no say over is untouched")
    check(
        p.apply_known([dict(stored_unknown)], {})[0]["status"] == "unknown",
        "apply_known: nothing known means every unknown/known row reads unknown",
    )
    # an IP-only host (no MAC) is looked up by IP, exactly as mark_known itself stores it
    ip_only = {"ip": "10.0.0.9", "mac": "", "status": "unknown", "rogue": True, "label": ""}
    check(
        p.apply_known([dict(ip_only)], {("", "10.0.0.9"): "kiosk"})[0]["status"] == "known",
        "apply_known: a MAC-less host is looked up by its IP",
    )

    # ── 1.2.3 (Q100 b): _reserve_scan is the ONE atomic path for both callers ──
    class _ReserveDB:
        """Simulates the database's own WHERE NOT EXISTS: the second reservation for a subnet that
        already has one pending inserts nothing (rowcount 0)."""

        def __init__(self):
            self.pending = set()
            self.log = []

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.log.append((" ".join(sql.split()), params))
            if sql.strip().startswith("INSERT INTO nd_scan_jobs"):
                sid = params[0]
                if sid in self.pending:
                    self.rowcount = 0
                else:
                    self.pending.add(sid)
                    self.rowcount = 1
                    self.lastrowid = 99

        def fetchall(self):
            return []

        def commit(self):
            pass

        def close(self):
            pass

    rdb = _ReserveDB()
    p._get_db = lambda: rdb
    first = p._reserve_scan(5)
    second = p._reserve_scan(5)
    check(
        first == 99 and second is None,
        f"_reserve_scan: a second reservation for a pending subnet gets None (got {first}, {second})",
    )
    check(p._reserve_scan(6) == 99, "_reserve_scan: a different subnet is unaffected")

    # ── 1.2.3 (Q100 c): the poll route uses subnet_or_404, not the flashing assert_subnet_access ──
    _stub_jen_plugin_api()
    p.jsonify = lambda payload: payload
    p._get_db = lambda: FakeDB(
        lambda sql, params: {
            "id": 1,
            "status": "done",
            "started_at": None,
            "finished_at": None,
            "hosts_found": 1,
            "rogue_count": 0,
            "error": None,
        }
    )
    ok_result = p.api_scan_status(1)
    check(
        ok_result.get("status") == "done" if isinstance(ok_result, dict) else False,
        f"api_scan_status: an accessible subnet still answers (got {ok_result})",
    )
    refused = p.api_scan_status(999)
    check(
        isinstance(refused, tuple) and refused[1] == 404,
        f"api_scan_status: an inaccessible/unknown subnet is a 404, not a flash (got {refused})",
    )

    # ── 1.2.4: the Create Reservation link carries subnet_id=, not subnet= ──
    # Jen's own add_reservation() route only ever reads subnet_id (subnet= is
    # accepted as an alias, but the canonical name is what every link should
    # send). render_template is stubbed above to return its own kwargs rather
    # than real HTML, so this reads the template SOURCE directly instead.
    with open(os.path.join(ROOT, "templates", "network_discovery", "results.html"), encoding="utf-8") as f:
        results_html = f.read()
    reservation_line = next(
        (line for line in results_html.splitlines() if "/reservations/add?" in line),
        "",
    )
    check(
        "subnet_id={{ subnet_id" in reservation_line,
        f"results.html: the Create Reservation link must carry subnet_id= (got: {reservation_line!r})",
    )
    check(
        "&subnet={{" not in reservation_line,
        f"results.html: the Create Reservation link must not still carry the wrong subnet= alias (got: {reservation_line!r})",
    )
    check(
        "h.ip|urlencode" in reservation_line and "subnet_id|urlencode" in reservation_line,
        f"results.html: the Create Reservation link's values must be urlencoded (got: {reservation_line!r})",
    )

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
    check(
        len(calls["investigation"]) == 1
        and calls["investigation"][0][0] == ("network-discovery",)
        and calls["investigation"][0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.3.0: the investigation provider ────────────────────────────────────
    ns = types.SimpleNamespace
    subject = ns(
        mac="AA:BB:CC:DD:EE:01", ip="10.1.0.5", leases4=[{"ip": "10.1.0.5"}, {"ip": "10.1.0.6"}, {"ip": "x"}],
        reservations=[{"ip": "10.1.0.7"}],
    )  # fmt: skip
    check(
        p.subject_addresses(subject) == ["10.1.0.5", "10.1.0.6", "10.1.0.7"],
        "subject_addresses: the typed address, the leases and the reservations, validated and de-duplicated",
    )
    check(p.investigation_card([]) is None, "investigation_card: a client no scan has seen adds no card")
    import datetime as _dt

    seen = _dt.datetime(2026, 10, 1, 8, 30)
    row = {
        "ip": "10.1.0.5", "mac": "aa:bb:cc:dd:ee:01", "hostname": "desk", "status": "lease", "rogue": 0, "label": "",
        "vendor": "Dell", "device_type": "pc", "discovered_at": seen, "subnet_id": 1,
    }  # fmt: skip
    card = p.investigation_card([row])
    check(
        card["status"] == "ok" and "10.1.0.5 (lease), vendor Dell" in card["summary"],
        f"investigation_card: a known host is an ok card (got {card['summary']!r})",
    )
    check(
        {"label": "Name seen", "value": "desk"} in card["rows"]
        and {"label": "Found by the scan at", "value": "2026-10-01 08:30 UTC"} in card["rows"]
        and card["rows"][0]["href"] == "/network/discovery/results/1",
        "investigation_card: the name seen, when it was found, and a link to that subnet's results",
    )
    check(
        all("port" not in r["label"].lower() for r in card["rows"]),
        "investigation_card: no ports are claimed - the scan does not store them",
    )
    unknown = p.investigation_card([dict(row, status="unknown", rogue=1)])
    check(
        unknown["status"] == "warn" and "nothing Jen knows accounts for it" in unknown["summary"],
        f"investigation_card: a host still unknown is a warn card (got {unknown['summary']!r})",
    )
    many = p.investigation_card([dict(row, subnet_id=i) for i in range(1, 4)])
    check(
        "2 more results" in many["summary"],
        f"investigation_card: more results in other scans are counted (got {many['summary']!r})",
    )

    # the impure provider, end to end through the plugin's own query
    # (earlier checks replaced `_load_known` on this module; the provider's own reads are restored here)
    p._load_known = types.FunctionType(
        load_plugin()._load_known.__code__, p.__dict__, "_load_known"
    )  # the real one, on p's own globals
    queries = []

    def answer(sql, params):
        queries.append((sql, params))
        if "FROM nd_known_hosts" in sql:
            return []
        return [dict(row)]

    fdb = FakeDB(answer)
    p._get_db = lambda: fdb
    got = p._investigate(subject, {1}, False)
    sql, params = queries[0]
    check(
        got is not None and got["href"] == "/network/discovery" and got["status"] == "ok",
        f"_investigate: the card for a seeded client, linking to the plugin's own page (got {got})",
    )
    check(
        "j.subnet_id IN (%s)" in sql
        and "r.mac=%s" in sql
        and "r.ip IN (%s,%s,%s)" in sql
        and params == (1, "aa:bb:cc:dd:ee:01", "10.1.0.5", "10.1.0.6", "10.1.0.7"),
        f"_investigate: the caller's scope, the MAC and the addresses are bound parameters of the one query (got {params})",
    )
    check("j2.status = 'done'" in sql, "_investigate: only each subnet's newest finished scan is read")
    queries.clear()
    fdb = FakeDB(answer)
    p._get_db = lambda: fdb
    check(
        p._investigate(subject, set(), False) is None and queries == [],
        "_investigate: a caller who may see no subnet runs no query at all",
    )
    queries.clear()
    p._investigate(subject, None, True)
    check("1=1" in queries[0][0], "_investigate: an unrestricted caller's scope is 1=1")
    queries.clear()
    check(
        p._investigate(ns(mac="", ip="", leases4=[], reservations=[]), None, True) is None and queries == [],
        "_investigate: a subject with no MAC and no address runs no query",
    )
    p._get_db = lambda: FakeDB(lambda sql, params: [])
    check(p._investigate(subject, {1}, False) is None, "_investigate: an unknown client gets None")
    p._get_db = lambda: FakeDB(
        lambda sql, params: [] if "nd_known_hosts" in sql else [dict(row, status="unknown", rogue=1)]
    )
    check(
        p._investigate(subject, {1}, False)["status"] == "warn",
        "_investigate: an unknown host the known-hosts list does not cover stays a warn card",
    )
    p._get_db = lambda: FakeDB(
        lambda sql, params: (
            [{"mac": "aa:bb:cc:dd:ee:01", "ip": "", "note": "mine"}]
            if "nd_known_hosts" in sql
            else [dict(row, status="unknown", rogue=1)]
        )
    )
    check(
        p._investigate(subject, {1}, False)["status"] == "ok",
        "_investigate: a host the operator marked known is no longer a warning",
    )

    # ── 1.3.1: the scan treats only a CURRENT lease as in Kea (Jen's ACTIVE_LEASE4, never a bare state = 0) ──
    q = load_plugin()
    _stub_jen_plugin_api()
    kfdb = FakeDB(lambda sql, params: [{"ip": "10.0.0.7", "mac_hex": "AABBCCDDEE07"}] if "FROM lease4" in sql else [])
    q._get_kea_db = lambda: kfdb
    lease_ips, lease_macs, _res_ips, _res_macs = q._load_kea(1)
    lease_sql = next(s for s, _ in kfdb.log if "FROM lease4" in s)
    check(
        "state = 0 AND expire > NOW()" in lease_sql and "state=0" not in lease_sql,
        f"_load_kea: the lease query asks for a current lease, not a bare state = 0 (got {lease_sql!r})",
    )
    check(lease_ips == {"10.0.0.7"} and lease_macs == {"aa:bb:cc:dd:ee:07"}, "_load_kea: the rows are read as before")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
