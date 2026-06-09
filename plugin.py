"""
Network Discovery plugin for Jen — v1.0.0
Scans subnets for devices not in the Kea lease table.
Requires nmap on the Jen host (sudo apt install nmap).
"""
import ipaddress
import json
import logging
import shutil
import subprocess
import threading
from datetime import datetime, timezone

from flask import (Blueprint, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

bp = Blueprint("network_discovery", __name__,
               template_folder="templates",
               url_prefix="/network/discovery")

_scan_lock = threading.Lock()


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

def _arp_scan_available():
    return shutil.which("arp-scan") is not None


# ── Scanning ──────────────────────────────────────────────────────────────────

def _scan_subnet(subnet_id: int, cidr: str) -> dict:
    """
    Scan a subnet using nmap (preferred) or arp-scan.
    Returns dict with lists: hosts [{ip, mac, hostname}]
    """
    hosts = []
    try:
        if _nmap_available():
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--host-timeout", "5s", cidr,
                 "--oG", "-"],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.splitlines():
                if not line.startswith("Host:"):
                    continue
                parts = line.split()
                ip = parts[1] if len(parts) > 1 else ""
                hostname = ""
                if len(parts) > 2:
                    h = parts[2].strip("()")
                    hostname = h if h and h != ip else ""
                if ip:
                    hosts.append({"ip": ip, "mac": "", "hostname": hostname})
        elif _arp_scan_available():
            result = subprocess.run(
                ["arp-scan", "--localnet", cidr],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip().lower() if len(parts) > 1 else ""
                    hostname = parts[2].strip() if len(parts) > 2 else ""
                    try:
                        ipaddress.IPv4Address(ip)
                        hosts.append({"ip": ip, "mac": mac, "hostname": hostname})
                    except ValueError:
                        pass
        else:
            return {"error": "nmap or arp-scan required. Install with: sudo apt install nmap"}
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out"}
    except Exception as e:
        return {"error": str(e)}

    return {"hosts": hosts}


def _cross_reference_kea(hosts: list, subnet_id: int) -> list:
    """
    For each discovered host, check if it's in Kea leases or reservations.
    Returns enriched host list with in_kea and rogue flags.
    """
    kea_ips = set()
    kea_macs = set()
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(address) as ip FROM lease4 WHERE state=0 AND subnet_id=%s",
                (subnet_id,)
            )
            for row in cur.fetchall():
                kea_ips.add(row["ip"])
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) as ip FROM hosts WHERE dhcp4_subnet_id=%s",
                (subnet_id,)
            )
            for row in cur.fetchall():
                kea_ips.add(row["ip"])
        kdb.close()
    except Exception as e:
        logger.error(f"Network Discovery: Kea cross-reference error: {e}")

    enriched = []
    for host in hosts:
        in_kea = host["ip"] in kea_ips
        enriched.append({
            **host,
            "in_kea": in_kea,
            "rogue": not in_kea,
        })
    return enriched


def _run_scan_job(subnet_id: int, cidr: str) -> int:
    """Run a full scan job, store results in DB. Returns job_id."""
    db = _get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO nd_scan_jobs (subnet_id, status) VALUES (%s, 'running')",
                (subnet_id,)
            )
            job_id = cur.lastrowid
        db.commit()

        result = _scan_subnet(subnet_id, cidr)

        if "error" in result:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE nd_scan_jobs SET status='error', finished_at=NOW() WHERE id=%s",
                    (job_id,)
                )
            db.commit()
            db.close()
            return job_id

        hosts = _cross_reference_kea(result["hosts"], subnet_id)
        rogue_count = sum(1 for h in hosts if h["rogue"])

        # Clear old results for this subnet, keep last 3 jobs
        with db.cursor() as cur:
            cur.execute("""
                DELETE FROM nd_scan_results WHERE job_id IN (
                    SELECT id FROM nd_scan_jobs
                    WHERE subnet_id=%s AND id != %s
                    ORDER BY started_at DESC LIMIT 100
                )
            """, (subnet_id, job_id))
            for host in hosts:
                cur.execute("""
                    INSERT INTO nd_scan_results
                        (job_id, ip, mac, hostname, in_kea, rogue)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        mac=VALUES(mac), hostname=VALUES(hostname),
                        in_kea=VALUES(in_kea), rogue=VALUES(rogue),
                        discovered_at=NOW()
                """, (job_id, host["ip"], host.get("mac",""),
                      host.get("hostname",""), host["in_kea"], host["rogue"]))
            cur.execute("""
                UPDATE nd_scan_jobs
                SET status='done', finished_at=NOW(),
                    hosts_found=%s, rogue_count=%s
                WHERE id=%s
            """, (len(hosts), rogue_count, job_id))
        db.commit()

        # Fire Jen alert if rogue devices found
        if rogue_count > 0:
            try:
                from jen.services.alerts import send_alert
                subnet_name = _subnet_map().get(subnet_id, {}).get("name", str(subnet_id))
                rogues = [h["ip"] for h in hosts if h["rogue"]]
                send_alert(
                    alert_type="rogue_device",
                    subject=f"⚠️ {rogue_count} rogue device(s) on {subnet_name}",
                    body=f"Network Discovery found {rogue_count} device(s) on {subnet_name} not in Kea:\n" +
                         "\n".join(f"  • {ip}" for ip in rogues[:10])
                )
            except Exception as e:
                logger.warning(f"Network Discovery: could not send alert: {e}")

    except Exception as e:
        logger.error(f"Network Discovery scan error: {e}")
        try:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE nd_scan_jobs SET status='error', finished_at=NOW() WHERE id=%s",
                    (job_id,)
                )
            db.commit()
        except Exception:
            pass
    finally:
        db.close()

    return job_id


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    scan_summary = {}
    try:
        db = _get_db()
        with db.cursor() as cur:
            for sid in subnet_map:
                cur.execute("""
                    SELECT j.id, j.status, j.started_at, j.finished_at,
                           j.hosts_found, j.rogue_count
                    FROM nd_scan_jobs j
                    WHERE j.subnet_id=%s
                    ORDER BY j.started_at DESC LIMIT 1
                """, (sid,))
                row = cur.fetchone()
                scan_summary[sid] = row or {}
        db.close()
    except Exception as e:
        logger.error(f"Network Discovery index error: {e}")

    nmap_ok   = _nmap_available()
    arpscan_ok = _arp_scan_available()
    scanner_ok = nmap_ok or arpscan_ok

    return render_template(
        "network_discovery/index.html",
        subnet_map=subnet_map,
        scan_summary=scan_summary,
        nmap_ok=nmap_ok,
        arpscan_ok=arpscan_ok,
        scanner_ok=scanner_ok,
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

    if not (_nmap_available() or _arp_scan_available()):
        flash("nmap or arp-scan is required. Install with: sudo apt install nmap", "error")
        return redirect(url_for("network_discovery.index"))

    cidr = subnet_map[subnet_id]["cidr"]

    # Run scan in background thread so the response returns immediately
    def _bg():
        with _scan_lock:
            _run_scan_job(subnet_id, cidr)

    t = threading.Thread(target=_bg, daemon=True)
    t.start()

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
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count
                FROM nd_scan_jobs WHERE subnet_id=%s
                ORDER BY started_at DESC LIMIT 1
            """, (subnet_id,))
            job = cur.fetchone()
            if job:
                cur.execute("""
                    SELECT ip, mac, hostname, in_kea, rogue, discovered_at
                    FROM nd_scan_results WHERE job_id=%s
                    ORDER BY inet_aton(ip)
                """, (job["id"],))
                hosts = cur.fetchall()
        db.close()
    except Exception as e:
        logger.error(f"Network Discovery results error: {e}")
        flash(f"Could not load results: {e}", "error")

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
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count
                FROM nd_scan_jobs WHERE subnet_id=%s
                ORDER BY started_at DESC LIMIT 1
            """, (subnet_id,))
            row = cur.fetchone()
        db.close()
        if row:
            return jsonify({
                "status": row["status"],
                "hosts_found": row["hosts_found"],
                "rogue_count": row["rogue_count"],
                "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
            })
        return jsonify({"status": "never"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


def register(app):
    app.register_blueprint(bp)
    logger.info("Network Discovery plugin registered")
