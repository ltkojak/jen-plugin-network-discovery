# Network Discovery — Jen Plugin

Scan your subnets and account for every device on them. Finds every live host on a subnet, records its MAC where the network allows it, and names what each one is — a Kea lease or reservation, the subnet's own gateway/DNS/Kea/Jen addresses, an IPAM Lite entry, a device Jen has seen before, or one you marked known — so only what's genuinely unaccounted for is *unknown*, and a Jen alert fires only for an unknown device the previous scan hadn't seen.

> **IPv4 only.** As of Jen v5.0's IPv6 rollout, active scanning here only covers IPv4 subnets — there's no IPv6 equivalent of an address-space sweep at homelab scale. IPv6 devices are visible on Jen's own Devices page (read from Kea's lease table directly, not scanned) instead. This isn't a bug or a gap to report — it's a deliberate v5.0 scope decision.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.57.0 or later (v1.1.x runs on 5.34.0+)
- `nmap` on the Jen host — Settings → Plugins offers an **Install nmap** button on a systemd host (through Jen's root-run plugin service); elsewhere:
  ```bash
  sudo apt install nmap
  ```

## How a scan works

Jen runs as an unprivileged service user, so nmap can't send raw packets — `nmap -sn` degrades to TCP connect() probes (ports 22, 80, 443, 445, 3389, 8080, 8443, 9100) and reports no MAC addresses. The plugin compensates:

- **On a subnet the Jen host is directly attached to**, each probe makes the kernel ARP for the target first, and every host that exists answers ARP whether or not it answers TCP. Right after the sweep the plugin reads the kernel neighbour table (`ip -4 neigh`): every freshly-reachable entry in the subnet is a found host, with its MAC, even if nmap itself saw nothing.
- **On a routed subnet** there are no neighbour entries, so only hosts answering one of the probed ports are found, without MACs.

The MAC is what makes the cross-reference reliable: a known device whose lease IP changed since the last scan is still recognised by MAC instead of being flagged every time.

## What a host is

Each found host gets one status, first match wins: `lease` (an active Kea lease, by IP or MAC) → `reservation` (a Kea host reservation, this subnet's or a global one) → `infrastructure` (the gateway, DNS servers, the Kea server, the Jen host, network/broadcast — from Jen's subnet context) → `ipam` (an IPAM Lite static/planned entry, when that plugin is installed) → `device` (a device Jen has seen before with no lease right now) → `known` (marked "I know this one") → `unknown`. Only `unknown` alerts. Vendor and device type come from Jen's OUI table.

## Features

- Per-subnet scan cards showing last scan time, hosts found, unknown count, and the reason if a scan failed
- Manual scan per subnet (background, auto-refreshing) and **scheduled scans** (superadmin; every 6/12/24 h or weekly, through Jen's periodic-job hook); a second scan of a subnet already mid-scan is refused; subnets larger than a /20 are refused with a reason and the nmap timeout scales with the subnet
- Results page: IP, hostname/label, vendor, MAC, status (filter by any), what changed since the previous scan, CSV export; per host: **Known** (never alert again, with a note), **create reservation** (prefilled), **add IPAM entry**
- Keeps the last 3 scans per subnet
- Fires its own "Rogue Device" alert (opt a channel into it under Settings → Alerts) — only for *unknown* hosts the previous scan hadn't seen, compared by MAC so an IP hop doesn't re-alert; the alert lists hostname, vendor and MAC. A new unknown also writes a `discovery.unknown` event to Jen's Timeline
- Discovered hosts show up in Jen's global search by MAC, IP, hostname, label or vendor, with when they were last seen
- Respects Jen subnet access control — restricted users only see and scan their assigned subnets; scanning and marking a host known both need admin — viewers are read-only. Known applies to every subnet Jen scans; marking needs admin

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Network Discovery. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/network-discovery/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute or an un-nonce'd `<script>` (Jen's CSP executes neither), `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
