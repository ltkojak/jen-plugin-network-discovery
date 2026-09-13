# Network Discovery — Jen Plugin

Scan your subnets for devices not in the Kea DHCP lease table. Finds every live host on a subnet, records its MAC where the network allows it, flags devices Kea doesn't know about, and fires a Jen alert when an unknown device appears that the previous scan hadn't seen.

> **IPv4 only.** As of Jen v5.0's IPv6 rollout, active scanning here only covers IPv4 subnets — there's no IPv6 equivalent of an address-space sweep at homelab scale. IPv6 devices are visible on Jen's own Devices page (read from Kea's lease table directly, not scanned) instead. This isn't a bug or a gap to report — it's a deliberate v5.0 scope decision.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v3.6.0 or later
- `nmap` on the Jen host:
  ```bash
  sudo apt install nmap
  ```

## How a scan works

Jen runs as an unprivileged service user, so nmap can't send raw packets — `nmap -sn` degrades to TCP connect() probes (ports 22, 80, 443, 445, 3389, 8080, 8443, 9100) and reports no MAC addresses. The plugin compensates:

- **On a subnet the Jen host is directly attached to**, each probe makes the kernel ARP for the target first, and every host that exists answers ARP whether or not it answers TCP. Right after the sweep the plugin reads the kernel neighbour table (`ip -4 neigh`): every freshly-reachable entry in the subnet is a found host, with its MAC, even if nmap itself saw nothing.
- **On a routed subnet** there are no neighbour entries, so only hosts answering one of the probed ports are found, without MACs.

The MAC is what makes the Kea cross-reference reliable: a known device whose lease IP changed since the last scan is still recognised by MAC instead of being flagged rogue every time.

## Features

- Per-subnet scan cards showing last scan time, total hosts found, and rogue count
- Manual scan trigger per subnet — runs in the background, auto-refreshes when done; a second scan of a subnet already mid-scan is refused
- Results page with full host table: IP, hostname, MAC, Kea status (known/rogue); filter All / Rogue / Known
- Keeps the last 3 scans per subnet
- Fires Jen's `rogue_device` alert (opt a channel into it under Settings → Alerts) — only for unknown devices the previous scan hadn't seen, so a permanently-unmanaged device doesn't page you every time
- Respects Jen subnet access control — restricted users only see and scan their assigned subnets

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Network Discovery. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/network-discovery/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler or an un-nonce'd `<script>` (Jen's CSP executes neither), `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
