"""
Network Discovery plugin for Jen.
Scans subnets for devices and says what each one IS, using everything
Jen already knows, before calling anything "unknown".
Requires nmap on the Jen host — Settings → Plugins can install it (Jen
5.30.0+, systemd hosts); elsewhere `sudo apt install nmap`.
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

What a found host is (v1.1.0)
─────────────────────────────
Each host gets ONE status, first match wins:

  lease           an active Kea lease (by IP, or by MAC)
  reservation     a Kea host reservation — this subnet's or a global one
  infrastructure  the gateway, a DNS server, the Kea server, the Jen
                  host, network/broadcast — from Jen's subnet_context
  ipam            an IPAM Lite static/planned entry (by IP or MAC),
                  when that plugin is installed
  device          a device Jen has seen before (the devices table, by
                  MAC) that has no lease right now — a static host
  known           an address/MAC the operator marked "I know this one"
  unknown         nothing above — the only status that alerts

The old `in_kea` / `rogue` columns are kept and derived (rogue means
unknown) so nothing that read them breaks.
"""

import contextlib
import csv
import io
import ipaddress
import logging
import os as _os
import shutil
import subprocess
import threading
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

PLUGIN_ID = "network-discovery"

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
_STALE_RUNNING_MINUTES = 30

# nmap's unprivileged -sn is a TCP connect() sweep; widening it past the
# default 80/443 catches printers (9100), Windows (445/3389), SSH boxes
# and the usual web-UI ports on routed subnets where ARP can't help.
_NMAP_PROBE_PORTS = "22,80,443,445,3389,8080,8443,9100"

# v1.1.0 — scope and time. Anything larger than a /20 (4,094 hosts) is
# refused outright rather than timing out into a bare error; the timeout
# scales with the address count.
_MAX_SCAN_PREFIX = 20
_TIMEOUT_BASE_S = 60
_TIMEOUT_PER_HOST_S = 0.125
_TIMEOUT_CAP_S = 900

# Neighbour-table states that mean "the kernel just heard from this MAC".
# STALE is deliberately NOT here for adding hosts — a STALE entry can
# outlive the device by hours — but it still supplies a MAC for a host
# nmap independently confirmed is up.
_NEIGH_FRESH = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}
_NEIGH_DEAD = {"FAILED", "INCOMPLETE", "NONE"}

_STATUSES = ("lease", "reservation", "infrastructure", "ipam", "device", "known", "unknown")
_STATUS_LABELS = {
    "lease": "✓ Kea lease",
    "reservation": "✓ Kea reservation",
    "infrastructure": "◆ Infrastructure",
    "ipam": "📋 IPAM entry",
    "device": "🖥 Known device",
    "known": "👍 Marked known",
    "unknown": "⚠ Unknown",
}
_INFRA_LABELS = {
    "gateway": "Gateway",
    "dns": "DNS server",
    "kea-server": "Kea server",
    "jen-host": "Jen host",
    "network": "Network",
    "broadcast": "Broadcast",
}

# Scheduled scans (v1.1.0): the periodic hook ticks this often and runs
# whatever subnets are due; the per-subnet interval is in nd_settings.
_SCHEDULE_TICK_MINUTES = 30
_SCHEDULE_CHOICES = (0, 6, 12, 24, 168)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _accessible_subnets():
    from jen.plugin_api import get_accessible_subnet_map

    return get_accessible_subnet_map()


def _is_superadmin():
    return getattr(current_user, "role", "") == "superadmin"


def _nmap_available():
    return shutil.which("nmap") is not None


def _can_install_nmap():
    """Jen 5.30.0's plugin os_packages path exists and this is a systemd
    host (the root-run plugin service can apt-install nmap)."""
    try:
        from jen.plugin_api import is_systemd_host

        return bool(is_systemd_host())
    except Exception:
        return False


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


def _safe_row(values):
    try:
        from jen.plugin_api import safe_row

        return safe_row(values)
    except Exception:
        out = []
        for v in values:
            s = "" if v is None else str(v)
            out.append(f"'{s}" if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s)
        return out


def _hex_to_mac(hex_str):
    return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2)).lower()


# ── Scanning ──────────────────────────────────────────────────────────────────


def scan_timeout_for(network):
    """Seconds nmap gets for this subnet: a floor plus a per-host share,
    capped. A /24 gets ~92 s, a /20 the cap."""
    return int(min(_TIMEOUT_CAP_S, _TIMEOUT_BASE_S + network.num_addresses * _TIMEOUT_PER_HOST_S))


def scan_scope_error(cidr):
    """Why a subnet can't be scanned, or None."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return f"Invalid subnet CIDR: {cidr}"
    if network.prefixlen < _MAX_SCAN_PREFIX:
        return (
            f"{cidr} is larger than a /{_MAX_SCAN_PREFIX} ({network.num_addresses:,} addresses) — an unprivileged "
            "connect() sweep of that many hosts takes far too long; scan a smaller subnet."
        )
    return None


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
        return {"error": "nmap is not installed on the Jen host"}
    scope = scan_scope_error(cidr)
    if scope:
        return {"error": scope}
    network = ipaddress.IPv4Network(cidr, strict=False)
    timeout = scan_timeout_for(network)
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", "--host-timeout", "5s", "-PS" + _NMAP_PROBE_PORTS, cidr, "--oG", "-"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"nmap did not finish within {timeout}s"}
    except Exception as e:
        logger.error(f"Network Discovery: nmap failed: {e}")
        return {"error": "nmap could not be run — see the Jen log"}
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        logger.error(f"Network Discovery: nmap exited {result.returncode}: {detail[-1] if detail else ''}")
        return {"error": f"nmap exited with status {result.returncode} — see the Jen log"}

    hosts = _parse_nmap_greppable(result.stdout)
    return {"hosts": _merge_neighbours(hosts, _neighbour_table(network))}


# ── What Jen knows ────────────────────────────────────────────────────────────


def _subnet_ctx(subnet_id, cidr):
    """Jen's subnet_context (5.30.0) — gateway, DNS, Kea/Jen hosts — else
    just network/broadcast."""
    try:
        from jen.plugin_api import subnet_context

        ctx = subnet_context(subnet_id)
        if ctx:
            return ctx
    except Exception as e:
        logger.warning(f"Network Discovery: subnet_context unavailable: {e}")
    infra = {}
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        if network.prefixlen < 31:
            infra[str(network.network_address)] = "network"
            infra[str(network.broadcast_address)] = "broadcast"
    except ValueError:
        pass
    return {"infrastructure": infra, "gateways": [], "dns": [], "pools": []}


def _load_kea(subnet_id):
    """(lease_ips, lease_macs, res_ips, res_macs) — reservations include
    global ones (dhcp4_subnet_id 0/NULL), which the old code missed.
    Only a type-0 (hw-address) identifier is a MAC."""
    lease_ips, lease_macs, res_ips, res_macs = set(), set(), set(), set()
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
                    lease_ips.add(row["ip"])
                if row.get("mac_hex") and len(row["mac_hex"]) == 12:
                    lease_macs.add(_hex_to_mac(row["mac_hex"]))
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS ident_hex, "
                "dhcp_identifier_type AS ident_type FROM hosts "
                "WHERE dhcp4_subnet_id=%s OR dhcp4_subnet_id=0 OR dhcp4_subnet_id IS NULL",
                (subnet_id,),
            )
            for row in cur.fetchall():
                if row["ip"]:
                    res_ips.add(row["ip"])
                if row.get("ident_hex") and row.get("ident_type") == 0 and len(row["ident_hex"]) == 12:
                    res_macs.add(_hex_to_mac(row["ident_hex"]))
    except Exception as e:
        logger.error(f"Network Discovery: Kea cross-reference error: {e}")
    finally:
        if kdb:
            kdb.close()
    return lease_ips, lease_macs, res_ips, res_macs


def _load_ipam(subnet_id):
    """(ips, macs) of IPAM Lite static/planned entries for this subnet —
    read directly from its table when the plugin is installed; ({} , {})
    when it isn't (the table doesn't exist)."""
    ips, macs = {}, {}
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT ip, mac, label, entry_status FROM ipam_static_entries "
                "WHERE subnet_kind='kea' AND subnet_id=%s AND entry_status IN ('static','planned')",
                (subnet_id,),
            )
            for row in cur.fetchall():
                label = row.get("label") or ""
                ips[row["ip"]] = label
                if row.get("mac"):
                    macs[row["mac"].lower()] = label
    except Exception:
        pass  # IPAM Lite not installed, or its table not yet migrated
    finally:
        if db:
            db.close()
    return ips, macs


def _load_devices(macs):
    """{mac: {name, owner, manufacturer, device_type, icon}} from Jen's
    devices table. One fixed statement per MAC."""
    out = {}
    macs = [m for m in macs if m]
    if not macs:
        return out
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            for mac in macs:
                cur.execute(
                    "SELECT device_name, owner, manufacturer, manufacturer_override, device_type, "
                    "device_type_override, device_icon, device_icon_override FROM devices WHERE mac=%s",
                    (mac,),
                )
                row = cur.fetchone()
                if row:
                    out[mac] = {
                        "name": row.get("device_name") or "",
                        "owner": row.get("owner") or "",
                        "manufacturer": row.get("manufacturer_override") or row.get("manufacturer") or "",
                        "device_type": row.get("device_type_override") or row.get("device_type") or "",
                        "icon": row.get("device_icon_override") or row.get("device_icon") or "",
                    }
    except Exception as e:
        logger.warning(f"Network Discovery: devices lookup failed: {e}")
    finally:
        if db:
            db.close()
    return out


def _load_known():
    """{(mac or '', ip or ''): note} — the operator's "I know this one" list."""
    out = {}
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, ip, note FROM nd_known_hosts")
            for row in cur.fetchall():
                out[((row.get("mac") or "").lower(), row.get("ip") or "")] = row.get("note") or ""
    except Exception as e:
        logger.warning(f"Network Discovery: known-hosts read failed: {e}")
    finally:
        if db:
            db.close()
    return out


def _vendor(mac, hostname):
    """(manufacturer, device_type, icon) from Jen's OUI table; blanks when
    there's no MAC or the module isn't there."""
    if not mac:
        return "", "", ""
    try:
        from jen.plugin_api import classify_device

        manufacturer, device_type, icon = classify_device(mac, hostname or "")
        return (
            (manufacturer if manufacturer != "Unknown" else ""),
            (device_type if device_type != "unknown" else ""),
            icon,
        )
    except Exception:
        return "", "", ""


def classify(hosts, kea, ctx, ipam, devices, known):
    """Pure. `kea` = (lease_ips, lease_macs, res_ips, res_macs); `ipam` =
    (ips, macs) → label; `devices` by MAC; `known` {(mac, ip): note}.
    Returns the hosts with status / label / vendor fields; first match
    wins in _STATUSES order."""
    lease_ips, lease_macs, res_ips, res_macs = kea
    ipam_ips, ipam_macs = ipam
    infra = ctx.get("infrastructure", {})
    out = []
    for h in hosts:
        ip, mac = h["ip"], (h.get("mac") or "").lower()
        hostname = h.get("hostname") or ""
        label = ""
        if ip in lease_ips or (mac and mac in lease_macs):
            status = "lease"
        elif ip in res_ips or (mac and mac in res_macs):
            status = "reservation"
        elif ip in infra:
            status = "infrastructure"
            label = _INFRA_LABELS.get(infra[ip], infra[ip])
        elif ip in ipam_ips or (mac and mac in ipam_macs):
            status = "ipam"
            label = ipam_ips.get(ip) or ipam_macs.get(mac, "")
        elif mac and mac in devices:
            status = "device"
            label = devices[mac].get("name") or ""
        elif (mac, "") in known or ("", ip) in known or (mac, ip) in known:
            status = "known"
            label = known.get((mac, "")) or known.get(("", ip)) or known.get((mac, ip)) or ""
        else:
            status = "unknown"
        manufacturer, device_type, icon = _vendor(mac, hostname)
        dev = devices.get(mac) if mac else None
        if dev:
            manufacturer = dev.get("manufacturer") or manufacturer
            device_type = dev.get("device_type") or device_type
            icon = dev.get("icon") or icon
            if not label and status in ("lease", "reservation"):
                label = dev.get("name") or ""
        out.append(
            {
                **h,
                "mac": mac,
                "status": status,
                "label": label,
                "vendor": manufacturer,
                "device_type": device_type,
                "icon": icon,
                "in_kea": status in ("lease", "reservation"),
                "rogue": status == "unknown",
            }
        )
    return out


def host_key(h):
    """What identifies a host across scans: its MAC when known, else IP."""
    return ("mac", h["mac"]) if h.get("mac") else ("ip", h["ip"])


def new_unknowns(current, previous_keys):
    """Pure: the unknown hosts of `current` whose key the previous scan
    didn't already report as unknown. `previous_keys` None = no previous
    scan → everything unknown is new."""
    unknown = [h for h in current if h["status"] == "unknown"]
    if previous_keys is None:
        return unknown
    return [h for h in unknown if host_key(h) not in previous_keys]


def delta(current, previous):
    """Pure: ({key: host} appeared, {key: host} gone) between two result
    lists, keyed by MAC when known else IP."""
    cur = {host_key(h): h for h in current}
    prev = {host_key(h): h for h in previous}
    appeared = [cur[k] for k in cur if k not in prev]
    gone = [prev[k] for k in prev if k not in cur]
    return appeared, gone


# ── Jobs ──────────────────────────────────────────────────────────────────────


def _previous_results(cur, subnet_id, current_job_id):
    """The rows of the most recent completed scan of this subnet before
    the current one, or None when there wasn't one."""
    cur.execute(
        "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND id != %s AND status='done' "
        "ORDER BY started_at DESC, id DESC LIMIT 1",
        (subnet_id, current_job_id),
    )
    prev = cur.fetchone()
    if not prev:
        return None
    cur.execute("SELECT ip, mac, hostname, status, rogue FROM nd_scan_results WHERE job_id=%s", (prev["id"],))
    rows = cur.fetchall()
    for r in rows:
        r["mac"] = (r.get("mac") or "").lower()
        r["status"] = r.get("status") or ("unknown" if r.get("rogue") else "lease")
    return rows


def _mark_job(db, job_id, status, error=None, hosts=0, unknown=0):
    with db.cursor() as cur:
        cur.execute(
            "UPDATE nd_scan_jobs SET status=%s, finished_at=NOW(), hosts_found=%s, rogue_count=%s, error=%s WHERE id=%s",
            (status, hosts, unknown, (error or "")[:255] or None, job_id),
        )
    db.commit()


def _run_scan_job(subnet_id, cidr, trigger="manual"):
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
            _mark_job(db, job_id, "error", result["error"])
            return job_id

        found = result["hosts"]
        ctx = _subnet_ctx(subnet_id, cidr)
        kea = _load_kea(subnet_id)
        ipam = _load_ipam(subnet_id)
        devices = _load_devices(sorted({h["mac"] for h in found if h.get("mac")}))
        hosts = classify(found, kea, ctx, ipam, devices, _load_known())
        unknown_count = sum(1 for h in hosts if h["status"] == "unknown")

        with db.cursor() as cur:
            previous = _previous_results(cur, subnet_id, job_id)
            prev_keys = None if previous is None else {host_key(r) for r in previous if r["status"] == "unknown"}
            fresh = new_unknowns(hosts, prev_keys)

            # Prune this subnet's history down to the newest _KEEP_JOBS
            # jobs (this one included) — one fixed statement per old job.
            cur.execute(
                "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND id != %s ORDER BY started_at DESC, id DESC",
                (subnet_id, job_id),
            )
            for old_id in [r["id"] for r in cur.fetchall()][_KEEP_JOBS - 1 :]:
                cur.execute("DELETE FROM nd_scan_results WHERE job_id=%s", (old_id,))
                cur.execute("DELETE FROM nd_scan_jobs WHERE id=%s", (old_id,))
            for h in hosts:
                cur.execute(
                    """
                    INSERT INTO nd_scan_results (job_id, ip, mac, hostname, in_kea, rogue, status, label, vendor, device_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        job_id,
                        h["ip"],
                        h.get("mac", ""),
                        h.get("hostname", ""),
                        h["in_kea"],
                        h["rogue"],
                        h["status"],
                        (h.get("label") or "")[:200],
                        (h.get("vendor") or "")[:100],
                        (h.get("device_type") or "")[:30],
                    ),
                )
        db.commit()
        _mark_job(db, job_id, "done", None, len(hosts), unknown_count)

        if fresh:
            _alert_new_unknowns(subnet_id, fresh, unknown_count, trigger)

    except Exception as e:
        logger.error(f"Network Discovery scan error: {e}")
        if job_id is not None:
            with contextlib.suppress(Exception):
                _mark_job(db, job_id, "error", "scan failed — see the Jen log")
    finally:
        db.close()

    return job_id


def _alert_new_unknowns(subnet_id, fresh, unknown_count, trigger):
    """Jen's `rogue_device` alert type (a channel opts into it under
    Settings → Alerts). subnet_id lets a subnet-scoped channel filter
    it like any other per-subnet alert."""
    try:
        from jen.plugin_api import send_alert

        subnet_name = _subnet_map().get(subnet_id, {}).get("name", str(subnet_id))
        lines = []
        for h in fresh[:10]:
            bits = [h["ip"]]
            if h.get("hostname"):
                bits.append(h["hostname"])
            if h.get("vendor"):
                bits.append(h["vendor"])
            if h.get("mac"):
                bits.append(h["mac"])
            lines.append("  • " + " · ".join(bits))
        listed = "\n".join(lines)
        if len(fresh) > 10:
            listed += f"\n  … and {len(fresh) - 10} more"
        send_alert(
            alert_type="rogue_device",
            subnet_id=subnet_id,
            subject=f"⚠️ {len(fresh)} new unknown device(s) on {subnet_name}",
            body=(
                f"Network Discovery ({trigger} scan) found {len(fresh)} device(s) on {subnet_name} it can't "
                f"account for — not a Kea lease or reservation, not infrastructure, not an IPAM entry, not a "
                f"device Jen has seen, not marked known — that the previous scan hadn't seen "
                f"({unknown_count} unknown in total):\n{listed}"
            ),
        )
    except Exception as e:
        logger.warning(f"Network Discovery: could not send alert: {e}")


def _expire_stale_running_jobs(cur):
    """A 'running' job older than _STALE_RUNNING_MINUTES is a leftover
    from a Jen restart mid-scan — its thread is gone. Without this the
    index shows it as 'Scanning…' forever and the poller never stops."""
    cur.execute(
        "UPDATE nd_scan_jobs SET status='error', error='interrupted (Jen restarted mid-scan)', finished_at=NOW() "
        "WHERE status='running' AND started_at < NOW() - INTERVAL %s MINUTE",
        (_STALE_RUNNING_MINUTES,),
    )


def _start_scan(subnet_id, cidr, trigger="manual"):
    def _bg():
        with _scan_lock:
            _run_scan_job(subnet_id, cidr, trigger)

    threading.Thread(target=_bg, daemon=True).start()


# ── Scheduling (v1.1.0, Jen 5.30.0 register_periodic) ─────────────────────────


def _schedules():
    """{subnet_id: every_hours} for subnets with a schedule set."""
    out = {}
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT subnet_id, every_hours FROM nd_settings WHERE every_hours > 0")
            for row in cur.fetchall():
                out[row["subnet_id"]] = int(row["every_hours"])
    except Exception as e:
        logger.warning(f"Network Discovery: could not read schedules: {e}")
    finally:
        if db:
            db.close()
    return out


def due_subnets(schedules, last_done, running, now):
    """Pure: subnet ids whose last completed scan is older than their
    interval (or never ran), excluding ones mid-scan."""
    due = []
    for sid, hours in schedules.items():
        if sid in running:
            continue
        last = last_done.get(sid)
        if last is None or last <= now - timedelta(hours=hours):
            due.append(sid)
    return due


def _scheduled_tick():
    """The periodic job: scan every subnet that's due, one after the
    other (the scan lock serialises them anyway)."""
    schedules = _schedules()
    if not schedules or not _nmap_available():
        return
    subnet_map = _subnet_map()
    last_done, running = {}, set()
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            _expire_stale_running_jobs(cur)
            for sid in schedules:
                cur.execute(
                    "SELECT status, finished_at FROM nd_scan_jobs WHERE subnet_id=%s ORDER BY started_at DESC, id DESC LIMIT 1",
                    (sid,),
                )
                row = cur.fetchone()
                if row and row["status"] == "running":
                    running.add(sid)
                elif row and row["status"] == "done" and row.get("finished_at"):
                    last_done[sid] = row["finished_at"].replace(tzinfo=timezone.utc)
        db.commit()
    except Exception as e:
        logger.warning(f"Network Discovery: schedule tick could not read job state: {e}")
        return
    finally:
        if db:
            db.close()
    for sid in due_subnets(schedules, last_done, running, datetime.now(timezone.utc)):
        info = subnet_map.get(sid)
        if not info or scan_scope_error(info["cidr"]):
            continue
        logger.info(f"Network Discovery: scheduled scan of {info['name']} ({info['cidr']})")
        with _scan_lock:
            _run_scan_job(sid, info["cidr"], trigger="scheduled")


# ── Routes ────────────────────────────────────────────────────────────────────


@bp.route("/")
@login_required
def index():
    subnet_map = _accessible_subnets()
    scan_summary = {}
    schedules = _schedules()
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            _expire_stale_running_jobs(cur)
            for sid in subnet_map:
                cur.execute(
                    """
                    SELECT j.id, j.status, j.started_at, j.finished_at, j.hosts_found, j.rogue_count, j.error
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
        schedules=schedules,
        schedule_choices=_SCHEDULE_CHOICES,
        scope_errors={sid: scan_scope_error(info["cidr"]) for sid, info in subnet_map.items()},
        scanner_ok=_nmap_available(),
        can_install_nmap=_can_install_nmap() and _is_superadmin(),
        is_superadmin=_is_superadmin(),
        plugin_id=PLUGIN_ID,
    )


@bp.route("/scan/<int:subnet_id>", methods=["POST"])
@login_required
def start_scan(subnet_id):
    from jen.plugin_api import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("network_discovery.index"))

    if not _nmap_available():
        flash(
            "nmap is not installed on the Jen host — install it from Settings → Plugins, or `sudo apt install nmap`.",
            "error",
        )
        return redirect(url_for("network_discovery.index"))

    cidr = subnet_map[subnet_id]["cidr"]
    scope = scan_scope_error(cidr)
    if scope:
        flash(scope, "error")
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

    _start_scan(subnet_id, cidr)
    flash(f"Scan started for {subnet_map[subnet_id]['name']}. Results will appear in a moment.", "success")
    return redirect(url_for("network_discovery.index"))


@bp.route("/schedule/<int:subnet_id>", methods=["POST"])
@login_required
def set_schedule(subnet_id):
    """v1.1.0 — per-subnet scan interval (hours; 0 = off). Superadmin: it
    starts unattended scanning."""
    if not _is_superadmin():
        flash("Only a superadmin can schedule scans.", "error")
        return redirect(url_for("network_discovery.index"))
    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("network_discovery.index"))
    raw = request.form.get("every_hours", "0").strip()
    hours = int(raw) if raw.isdigit() else -1
    if hours not in _SCHEDULE_CHOICES:
        flash("Pick one of the offered intervals.", "error")
        return redirect(url_for("network_discovery.index"))
    scope = scan_scope_error(subnet_map[subnet_id]["cidr"]) if hours else None
    if scope:
        flash(scope, "error")
        return redirect(url_for("network_discovery.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO nd_settings (subnet_id, every_hours) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE every_hours=VALUES(every_hours)",
                (subnet_id, hours),
            )
        db.commit()
        name = subnet_map[subnet_id]["name"]
        flash(f"{name}: scheduled scans {'off' if not hours else f'every {hours} h'}.", "success")
        try:
            from jen.plugin_api import audit

            audit("ND_SCHEDULE", name, f"subnet={subnet_id} every_hours={hours}")
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Network Discovery: could not save schedule: {e}")
        flash("Could not save the schedule — is the plugin's database migration applied?", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("network_discovery.index"))


def _load_results(cur, job_id):
    cur.execute(
        """
        SELECT ip, mac, hostname, in_kea, rogue, status, label, vendor, device_type, discovered_at
        FROM nd_scan_results WHERE job_id=%s
        ORDER BY inet_aton(ip)
        """,
        (job_id,),
    )
    rows = cur.fetchall()
    for r in rows:
        r["mac"] = (r.get("mac") or "").lower()
        r["status"] = r.get("status") or ("unknown" if r.get("rogue") else "lease")
        r["label"] = r.get("label") or ""
        r["vendor"] = r.get("vendor") or ""
    return rows


@bp.route("/results/<int:subnet_id>")
@login_required
def results(subnet_id):
    from jen.plugin_api import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))

    subnet_map = _subnet_map()
    if subnet_id not in subnet_map:
        flash("Subnet not found.", "error")
        return redirect(url_for("network_discovery.index"))

    job = None
    hosts = []
    appeared, gone = [], []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count, error
                FROM nd_scan_jobs WHERE subnet_id=%s
                ORDER BY started_at DESC, id DESC LIMIT 1
                """,
                (subnet_id,),
            )
            job = cur.fetchone()
            if job:
                hosts = _load_results(cur, job["id"])
                previous = _previous_results(cur, subnet_id, job["id"])
                if previous is not None:
                    appeared, gone = delta(hosts, previous)
    except Exception as e:
        logger.error(f"Network Discovery results error: {e}")
        flash("Could not load scan results. Check the Jen log for details.", "error")
    finally:
        if db:
            db.close()

    counts = {s: sum(1 for h in hosts if h["status"] == s) for s in _STATUSES}
    ipam_installed = _ipam_installed()
    return render_template(
        "network_discovery/results.html",
        subnet_map=subnet_map,
        subnet_id=subnet_id,
        subnet=subnet_map.get(subnet_id, {}),
        job=job,
        hosts=hosts,
        counts=counts,
        statuses=_STATUSES,
        status_labels=_STATUS_LABELS,
        appeared=appeared,
        gone=gone,
        ipam_installed=ipam_installed,
    )


def _ipam_installed():
    try:
        from jen.plugin_api import installed_plugins

        return any(p.get("id") == "ipam" and p.get("enabled") for p in installed_plugins())
    except Exception:
        return False


@bp.route("/results/<int:subnet_id>/export")
@login_required
def export_results(subnet_id):
    from jen.plugin_api import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))
    rows = []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND status='done' ORDER BY started_at DESC, id DESC LIMIT 1",
                (subnet_id,),
            )
            job = cur.fetchone()
            if job:
                rows = _load_results(cur, job["id"])
    except Exception as e:
        logger.error(f"Network Discovery export error: {e}")
    finally:
        if db:
            db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "hostname", "mac", "status", "label", "vendor", "device_type", "discovered_at"])
    for r in rows:
        writer.writerow(
            _safe_row(
                [
                    r["ip"],
                    r.get("hostname") or "",
                    r["mac"],
                    r["status"],
                    r["label"],
                    r["vendor"],
                    r.get("device_type") or "",
                    r["discovered_at"].strftime("%Y-%m-%d %H:%M") if r.get("discovered_at") else "",
                ]
            )
        )
    name = _subnet_map().get(subnet_id, {}).get("name", str(subnet_id))
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=discovery-{subnet_id}.csv"
    logger.info(f"Network Discovery: exported {len(rows)} rows for {name}")
    return resp


@bp.route("/known/<int:subnet_id>", methods=["POST"])
@login_required
def mark_known(subnet_id):
    """v1.1.0 — "I know this one": never alert on this MAC (or IP, when
    there's no MAC) again; shows as `known` on every future scan.
    `action=forget` removes it."""
    from jen.plugin_api import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return redirect(url_for("network_discovery.index"))
    back = redirect(url_for("network_discovery.results", subnet_id=subnet_id))
    ip = request.form.get("ip", "").strip()
    mac = request.form.get("mac", "").strip().lower()
    note = request.form.get("note", "").strip()[:200]
    action = request.form.get("action", "add")
    try:
        if ip:
            ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return back
    if mac and not (len(mac) == 17 and all(c in "0123456789abcdef:" for c in mac)):
        flash("Invalid MAC address.", "error")
        return back
    if not mac and not ip:
        flash("Nothing to mark.", "error")
        return back
    key_mac, key_ip = (mac, "") if mac else ("", ip)
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            if action == "forget":
                cur.execute("DELETE FROM nd_known_hosts WHERE mac=%s AND ip=%s", (key_mac, key_ip))
            else:
                cur.execute(
                    "INSERT INTO nd_known_hosts (mac, ip, note, added_by) VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE note=VALUES(note), added_by=VALUES(added_by)",
                    (key_mac, key_ip, note, current_user.username),
                )
            # Reflect it in the latest results right away rather than
            # waiting for the next scan.
            cur.execute(
                "SELECT id FROM nd_scan_jobs WHERE subnet_id=%s AND status='done' ORDER BY started_at DESC, id DESC LIMIT 1",
                (subnet_id,),
            )
            job = cur.fetchone()
            if job:
                new_status = "unknown" if action == "forget" else "known"
                if key_mac:
                    cur.execute(
                        "UPDATE nd_scan_results SET status=%s, rogue=%s, label=%s WHERE job_id=%s AND mac=%s AND status IN ('unknown','known')",
                        (new_status, new_status == "unknown", note, job["id"], key_mac),
                    )
                else:
                    cur.execute(
                        "UPDATE nd_scan_results SET status=%s, rogue=%s, label=%s WHERE job_id=%s AND ip=%s AND status IN ('unknown','known')",
                        (new_status, new_status == "unknown", note, job["id"], key_ip),
                    )
                cur.execute(
                    "UPDATE nd_scan_jobs SET rogue_count=(SELECT COUNT(*) FROM nd_scan_results WHERE job_id=%s AND status='unknown') WHERE id=%s",
                    (job["id"], job["id"]),
                )
        db.commit()
        what = mac or ip
        flash(
            f"{what} {'forgotten — it will count as unknown again' if action == 'forget' else 'marked known — it will not alert again'}.",
            "success",
        )
        try:
            from jen.plugin_api import audit

            audit("ND_KNOWN_HOST", what, f"subnet={subnet_id} action={action} note={note}")
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Network Discovery: could not update known hosts: {e}")
        flash("Could not save — is the plugin's database migration applied?", "error")
    finally:
        if db:
            db.close()
    return back


@bp.route("/api/scan-status/<int:subnet_id>")
@login_required
def api_scan_status(subnet_id):
    """Poll endpoint for scan progress."""
    from jen.plugin_api import assert_subnet_access

    if not assert_subnet_access(subnet_id):
        return jsonify({"error": "Access denied"}), 403
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT id, status, started_at, finished_at, hosts_found, rogue_count, error
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
                    "error": row.get("error") or "",
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
    # v1.1.0 — scheduled scans through Jen's periodic-job hook (5.30.0).
    # Registration only; nothing starts here (create_app must stay pure).
    try:
        from jen.plugin_api import register_periodic

        register_periodic(PLUGIN_ID, "scheduled-scans", _scheduled_tick, _SCHEDULE_TICK_MINUTES)
    except Exception as e:
        logger.warning(f"Network Discovery: scheduled scans unavailable on this Jen: {e}")
    logger.info("Network Discovery plugin registered")
