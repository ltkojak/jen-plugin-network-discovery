"""
Network Discovery plugin for Jen.
Scans subnets for devices not in the Kea lease table.
Requires nmap on the Jen host (sudo apt install nmap).
Version lives in manifest.json — not duplicated here.

How a scan finds hosts (v1.0.3)
────────────────────────────────
Jen runs as an unprivileged service user, so nmap can't send raw
packets: `nmap -sn` degrades to TCP connect() probes against a handful
of common ports, and reports no MAC addresses at all. Two consequences,
and how they're handled:

  * On a subnet the Jen host is directly attached to, every one of
    those connect() attempts makes the kernel ARP for the target first
    — and every host that exists answers ARP whether or not it answers
    TCP. So right after the sweep, the kernel neighbour table holds a
    fresh (REACHABLE) entry, with MAC, for every live host on that
    link. `_neighbour_table()` reads it: REACHABLE entries inside the
    CIDR are added as found hosts even when nmap saw nothing, and any
    non-failed entry supplies the MAC for a host nmap did see.
  * On a routed subnet there are no neighbour entries for it, so only
    hosts answering one of the probed ports are found, without MACs.

The MAC is what makes the Kea cross-reference reliable: a known device
whose lease IP changed since Kea last saw it is still "known" by MAC
instead of being flagged rogue on every scan.
"""

import ipaddress
import logging
import os as _os
import shutil
import subprocess
import threading

from flask import Blueprint, flash, jsonify, redirect, render_template, url_for
from flask_login import login_required

logger = logging.getLogger(__name__)

bp = Blueprint(
    "network_discovery",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/network/discovery",
)

_scan_lock = threading.Lock()

# How many scan jobs (and their results) to keep per subnet, newest first.
_KEEP_JOBS = 3

# A job still 'running' after this long is a leftover from a Jen restart
# (the scan thread died with the process) — nothing will ever finish it.
_STALE_RUNNING_MINUTES = 10

# nmap's unprivileged -sn is a TCP connect() sweep; widening it past the
# default 80/443 catches printers (9100), Windows (445/3389), SSH boxes
# and the usual web-UI ports on routed subnets where ARP can't help.
_NMAP_PROBE_PORTS = "22,80,443,445,3389,8080,8443,9100"
_NMAP_TIMEOUT = 180

# Neighbour-table states that mean "the kernel just heard from this MAC".
# STALE is deliberately NOT here for adding hosts — a STALE entry can
# outlive the device by hours — but it still supplies a MAC for a host
# nmap independently confirmed is up.
_NEIGH_FRESH = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}
_NEIGH_DEAD = {"FAILED", "INCOMPLETE", "NONE"}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db():
    from jen.models.db import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.models.db import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen import extensions

    return extensions.SUBNET_MAP


def _accessible_subnets():
    from jen.services.access import get_accessible_subnet_map

    return get_accessible_subnet_map()


def _nmap_available():
    return shutil.which("nmap") is not None


def _ip_binary():
    """`ip` lives in /usr/sbin, which a service user's PATH may not have."""
    for candidate in ("ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"):
        found = (
            shutil.which(candidate)
            if "/" not in candidate
            else (candidate if _os.access(candidate, _os.X_OK) else None)
        )
        if found:
            return found
    return None


# ── Scanning ──────────────────────────────────────────────────────────────────


def _parse_nmap_greppable(text):
    """`nmap -sn --oG -` → [{ip, mac, hostname}]. Only up hosts are listed
    in greppable output for a ping scan; each is `Host: <ip> (<name>)`."""
    hosts = []
    for line in text.splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        ip = parts[1] if len(parts) > 1 else ""
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        hostname = ""
        if len(parts) > 2 and parts[2].startswith("("):
            h = parts[2].strip("()")
            hostname = h if h and h != ip else ""
        hosts.append({"ip": ip, "mac": "", "hostname": hostname})
    return hosts


def _parse_neighbours(text, network):
    """`ip -4 neigh show` → {ip: (mac, state)} for entries inside `network`
    that have a MAC and aren't dead. Lines look like
    `10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            addr = ipaddress.IPv4Address(parts[0])
        except ValueError:
            continue
        if addr not in network:
            continue
        mac = ""
        if "lladdr" in parts:
            i = parts.index("lladdr")
            if i + 1 < len(parts):
                mac = parts[i + 1].lower()
        state = parts[-1].upper() if parts else ""
        if not mac or state in _NEIGH_DEAD:
            continue
        out[str(addr)] = (mac, state)
    return out


def _neighbour_table(network):
    """Best effort — an empty dict on any failure (no `ip`, Docker with no
    view of the host's links, a routed subnet with no entries)."""
    ip_bin = _ip_binary()
    if not ip_bin:
        return {}
    try:
        result = subprocess.run([ip_bin, "-4", "neigh", "show"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        logger.warning(f"Network Discovery: could not read the neighbour table: {e}")
        return {}
    if result.returncode != 0:
        return {}
    return _parse_neighbours(result.stdout, network)


def _merge_neighbours(hosts, neighbours):
    """Attach MACs from the neighbour table to hosts nmap found, and add
    hosts the kernel just heard from that nmap missed (no open probe
    port). Pure; see the module docstring for why this is sound."""
    by_ip = {h["ip"]: h for h in hosts}
    for ip, (mac, state) in neighbours.items():
        if ip in by_ip:
            if not by_ip[ip]["mac"]:
                by_ip[ip]["mac"] = mac
        elif state in _NEIGH_FRESH:
            by_ip[ip] = {"ip": ip, "mac": mac, "hostname": ""}
    return sorted(by_ip.values(), key=lambda h: int(ipaddress.IPv4Address(h["ip"])))


def _scan_subnet(cidr):
    """Scan a subnet with nmap, enriched from the neighbour table.
    Returns {"hosts": [{ip, mac, hostname}]} or {"error": str}."""
    if not _nmap_available():
        return {"error": "nmap is required. Install with: sudo apt install nmap"}
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return {"error": f"Invalid subnet CIDR: {cidr}"}
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", "--host-timeout", "5s", "-PS" + _NMAP_PROBE_PORTS, cidr, "--oG", "-"],
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Scan timed out after {_NMAP_TIMEOUT}s"}
    except Exception as e:
        logger.error(f"Network Discovery: nmap failed: {e}")
        return {"error": "nmap could not be run — see the Jen log"}
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        logger.error(f"Network Discovery: nmap exited {result.returncode}: {detail[-1] if detail else ''}")
        return {"error": f"nmap exited with status {result.returncode} — see the Jen log"}

    hosts = _parse_nmap_greppable(result.stdout)
    return {"hosts": _merge_neighbours(hosts, _neighbour_table(network))}


def _cross_reference_kea(hosts, subnet_id):
    """Flag each discovered host in_kea / rogue by matching its IP against
    Kea's active leases and reservations for this subnet, or its MAC when
    the scan captured one (a known device whose IP changed is still
    known). Only a type-0 (hw-address) reservation identifier is a MAC —
    a client-id or DUID of the same length must not masquerade as one."""
    kea_ips = set()
    kea_macs = set()
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(address) AS ip, HEX(hwaddr) AS mac_hex FROM lease4 WHERE state=0 AND subnet_id=%s",
                (subnet_id,),
            )
            for row in cur.fetchall():
                if row["ip"]:
                    kea_ips.add(row["ip"])
                if row.get("mac_hex") and len(row["mac_hex"]) == 12:
                    kea_macs.add(_hex_to_mac(row["mac_hex"]))
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS ident_hex, "
                "dhcp_identifier_type AS ident_type FROM hosts WHERE dhcp4_subnet_id=%s",
                (subnet_id,),
            )
            for row in cur.fetchall():
                if row["ip"]:
                    kea_ips.add(row["ip"])
                if row.get("ident_hex") and row.get("ident_type") == 0 and len(row["ident_hex"]) == 12:
                    kea_macs.add(_hex_to_mac(row["ident_hex"]))
    except Exception as e:
        logger.error(f"Network Discovery: Kea cross-reference error: {e}")
    finally:
        if kdb:
            kdb.close()

    enriched = []
    for host in hosts:
        host_mac = (host.get("mac") or "").lower()
        in_kea = host["ip"] in kea_ips or (host_mac != "" and host_mac in kea_macs)
        enriched.append({**host, "in_kea": in_kea, "rogue": not in_kea})
    return enriched


def _hex_to_mac(hex_str):
    return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2)).lower()


def _previous_rogues(cur, subnet_id, current_job_id):
    """IPs flagged rogue by the most recent completed scan of this subnet
    before the current one — the baseline for "new unknowns"."""
    cur.execute(
        "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND id != %s AND status='done' "
        "ORDER BY started_at DESC, id DESC LIMIT 1",
        (subnet_id, current_job_id),
    )
    prev = cur.fetchone()
    if not prev:
        return None
    cur.execute("SELECT ip FROM nd_scan_results WHERE job_id=%s AND rogue=1", (prev["id"],))
    return {r["ip"] for r in cur.fetchall()}


def _run_scan_job(subnet_id, cidr):
    """Run a full scan job, store results in DB. Returns job_id."""
    db = _get_db()
    job_id = None
    try:
        with db.cursor() as cur:
            cur.execute("INSERT INTO nd_scan_jobs (subnet_id, status) VALUES (%s, 'running')", (subnet_id,))
            job_id = cur.lastrowid
        db.commit()

        result = _scan_subnet(cidr)

        if "error" in result:
            logger.error(f"Network Discovery: scan of {cidr} failed: {result['error']}")
            with db.cursor() as cur:
                cur.execute("UPDATE nd_scan_jobs SET status='error', finished_at=NOW() WHERE id=%s", (job_id,))
            db.commit()
            return job_id

        hosts = _cross_reference_kea(result["hosts"], subnet_id)
        rogue_count = sum(1 for h in hosts if h["rogue"])
        rogue_ips = [h["ip"] for h in hosts if h["rogue"]]

        with db.cursor() as cur:
            # "Alerts on new unknowns": what the previous completed scan
            # already reported as rogue is not news. Read it before the
            # prune below can remove that job.
            previous = _previous_rogues(cur, subnet_id, job_id)
            new_rogues = rogue_ips if previous is None else [ip for ip in rogue_ips if ip not in previous]

            # Prune this subnet's history down to the newest _KEEP_JOBS
            # jobs (this one included). v1.0.2: this used to be one
            # DELETE with an `IN (SELECT ... ORDER BY ... LIMIT 100)`
            # subquery, which MySQL and MariaDB both refuse ("doesn't yet
            # support LIMIT & IN subquery") — so every scan that actually
            # found hosts raised here, right after its INSERT, and was
            # recorded as 'error'. Pick the ids in Python instead.
            cur.execute(
                "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND id != %s ORDER BY started_at DESC, id DESC",
                (subnet_id, job_id),
            )
            # One fixed, parameterised statement per old job (never more
            # than a handful) rather than a runtime-built `IN (%s,%s,…)`.
            for old_id in [r["id"] for r in cur.fetchall()][_KEEP_JOBS - 1 :]:
                cur.execute("DELETE FROM nd_scan_results WHERE job_id=%s", (old_id,))
                cur.execute("DELETE FROM nd_scan_jobs WHERE id=%s", (old_id,))
            for host in hosts:
                cur.execute(
                    """
                    INSERT INTO nd_scan_results (job_id, ip, mac, hostname, in_kea, rogue)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (job_id, host["ip"], host.get("mac", ""), host.get("hostname", ""), host["in_kea"], host["rogue"]),
                )
            cur.execute(
                "UPDATE nd_scan_jobs SET status='done', finished_at=NOW(), hosts_found=%s, rogue_count=%s WHERE id=%s",
                (len(hosts), rogue_count, job_id),
            )
        db.commit()

        if new_rogues:
            _alert_new_rogues(subnet_id, new_rogues, rogue_count)

    except Exception as e:
        logger.error(f"Network Discovery scan error: {e}")
        if job_id is not None:
            try:
                with db.cursor() as cur:
                    cur.execute("UPDATE nd_scan_jobs SET status='error', finished_at=NOW() WHERE id=%s", (job_id,))
                db.commit()
            except Exception:
                pass
    finally:
        db.close()

    return job_id


def _alert_new_rogues(subnet_id, new_rogues, rogue_count):
    """Jen's `rogue_device` alert type (a channel opts into it under
    Settings → Alerts). subnet_id lets a subnet-scoped channel filter
    it like any other per-subnet alert."""
    try:
        from jen.services.alerts import send_alert

        subnet_name = _subnet_map().get(subnet_id, {}).get("name", str(subnet_id))
        listed = "\n".join(f"  • {ip}" for ip in new_rogues[:10])
        if len(new_rogues) > 10:
            listed += f"\n  … and {len(new_rogues) - 10} more"
        send_alert(
            alert_type="rogue_device",
            subnet_id=subnet_id,
            subject=f"⚠️ {len(new_rogues)} new unknown device(s) on {subnet_name}",
            body=(
                f"Network Discovery found {len(new_rogues)} device(s) on {subnet_name} not in Kea that the "
                f"previous scan hadn't seen ({rogue_count} unknown in total):\n{listed}"
            ),
        )
    except Exception as e:
        logger.warning(f"Network Discovery: could not send alert: {e}")


def _expire_stale_running_jobs(cur):
    """A 'running' job older than _STALE_RUNNING_MINUTES is a leftover
    from a Jen restart mid-scan — its thread is gone. Without this the
    index shows it as 'Scanning…' forever and the poller never stops."""
    cur.execute(
        "UPDATE nd_scan_jobs SET status='error', finished_at=NOW() "
        "WHERE status='running' AND started_at < NOW() - INTERVAL %s MINUTE",
        (_STALE_RUNNING_MINUTES,),
    )


# ── Routes ────────────────────────────────────────────────────────────────────


@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    scan_summary = {}
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            _expire_stale_running_jobs(cur)
            for sid in subnet_map:
                cur.execute(
                    """
                    SELECT j.id, j.status, j.started_at, j.finished_at, j.hosts_found, j.rogue_count
                    FROM nd_scan_jobs j WHERE j.subnet_id=%s
                    ORDER BY j.started_at DESC, j.id DESC LIMIT 1
                    """,
                    (sid,),
                )
                row = cur.fetchone()
                scan_summary[sid] = row or {}
        db.commit()
    except Exception as e:
        logger.error(f"Network Discovery index error: {e}")
    finally:
        if db:
            db.close()

    return render_template(
        "network_discovery/index.html",
        subnet_map=subnet_map,
        scan_summary=scan_summary,
        scanner_ok=_nmap_available(),
    )


@bp.route("/scan/<int:subnet_id>", methods=["POST"])
@login_required
def start_scan(subnet_id):
    from jen.services.access import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("network_discovery.index"))

    if not _nmap_available():
        flash("nmap is required. Install with: sudo apt install nmap", "error")
        return redirect(url_for("network_discovery.index"))

    # Refuse a second scan of a subnet that's genuinely mid-scan; a job
    # that only *looks* mid-scan because Jen restarted under it gets
    # expired first so it can't block the subnet forever.
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            _expire_stale_running_jobs(cur)
            cur.execute("SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND status='running' LIMIT 1", (subnet_id,))
            running = cur.fetchone()
        db.commit()
    except Exception as e:
        logger.error(f"Network Discovery: could not check for a running scan: {e}")
        running = None
    finally:
        if db:
            db.close()
    if running:
        flash(f"A scan of {subnet_map[subnet_id]['name']} is already in progress.", "warning")
        return redirect(url_for("network_discovery.index"))

    cidr = subnet_map[subnet_id]["cidr"]

    # Run in a background thread so the response returns immediately;
    # the lock serialises scans so two subnets never sweep at once.
    def _bg():
        with _scan_lock:
            _run_scan_job(subnet_id, cidr)

    threading.Thread(target=_bg, daemon=True).start()

    flash(f"Scan started for {subnet_map[subnet_id]['name']}. Results will appear in a moment.", "success")
    return redirect(url_for("network_discovery.index"))


@bp.route("/results/<int:subnet_id>")
@login_required
def results(subnet_id):
    from jen.services.access import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("network_discovery.index"))

    job = None
    hosts = []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count
                FROM nd_scan_jobs WHERE subnet_id=%s
                ORDER BY started_at DESC, id DESC LIMIT 1
                """,
                (subnet_id,),
            )
            job = cur.fetchone()
            if job:
                cur.execute(
                    """
                    SELECT ip, mac, hostname, in_kea, rogue, discovered_at
                    FROM nd_scan_results WHERE job_id=%s
                    ORDER BY inet_aton(ip)
                    """,
                    (job["id"],),
                )
                hosts = cur.fetchall()
    except Exception as e:
        logger.error(f"Network Discovery results error: {e}")
        flash("Could not load scan results. Check the Jen log for details.", "error")
    finally:
        if db:
            db.close()

    return render_template(
        "network_discovery/results.html",
        subnet_map=subnet_map,
        subnet_id=subnet_id,
        subnet=subnet_map.get(subnet_id, {}),
        job=job,
        hosts=hosts,
    )


@bp.route("/api/scan-status/<int:subnet_id>")
@login_required
def api_scan_status(subnet_id):
    """Poll endpoint for scan progress."""
    from jen.services.access import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return jsonify({"error": "Access denied"}), 403
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count
                FROM nd_scan_jobs WHERE subnet_id=%s
                ORDER BY started_at DESC, id DESC LIMIT 1
                """,
                (subnet_id,),
            )
            row = cur.fetchone()
        if row:
            return jsonify(
                {
                    "status": row["status"],
                    "hosts_found": row["hosts_found"],
                    "rogue_count": row["rogue_count"],
                    "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
                }
            )
        return jsonify({"status": "never"})
    except Exception as e:
        logger.error(f"Network Discovery scan-status error: {e}")
        return jsonify({"status": "error", "error": "Could not read scan status."})
    finally:
        if db:
            db.close()


def register(app):
    app.register_blueprint(bp)
    logger.info("Network Discovery plugin registered")
