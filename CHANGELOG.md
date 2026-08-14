# Network Discovery Plugin — Changelog

## [1.0.1] - 2026-08-15

### Fixed: three real bugs found comparing this repo against the bundled reference copy in jen-kea

None of these were caught earlier because this separate repo had
silently drifted out of sync with fixes already made to the bundled
copy in `jen-kea/plugins/network-discovery/` — the same pattern found
and fixed for IPAM Lite. Found by pulling this repo fresh and diffing
it directly against the bundled copy, rather than assuming the two
had stayed in sync.

### Security fix
**`/api/scan-status/<subnet_id>` had no subnet-access check.** Every
other route in this plugin (`/scan/<subnet_id>`, `/results/<subnet_id>`)
correctly calls `assert_subnet_access(subnet_id)` — this one didn't,
meaning a subnet-restricted admin could poll scan status and host/
rogue-device counts for any subnet, not just their own. Fixed by
adding the same check, matching the sibling routes exactly. Verified
directly: created a real admin restricted to one subnet, confirmed a
real request for a different subnet's scan status now correctly
returns 403, and confirmed their own subnet still works.

### Correctness fix
**Rogue-device matching was IP-only.** A `kea_macs` set was declared
but never populated or used — a known device with a MAC address
already in Kea, but a renewed or different current IP, was wrongly
flagged "rogue" on every scan. Now matches on IP OR MAC when the scan
method captured one (arp-scan reports MAC; nmap's `-sn` output doesn't
reliably, so IP-only remains the correct fallback there). Verified
directly against the real function: a device with a matching MAC but
different IP now correctly resolves as known instead of rogue.

### Security fix (CSRF)
All three POST forms across `index.html` and `results.html` (the
re-scan and scan-now buttons) were missing their `csrf_token` field —
every submission through any of them got rejected with a 403 "session
security token is missing or expired," regardless of session validity.
Verified directly: a real POST with no token confirmed 403, then the
same session's token confirmed the fix resolves it.

### Verification
All three fixes verified against this repo's own real code running
inside a real Jen instance — real database migrations, real login,
real session, real CSRF middleware enabled — not against the bundled
copy, not against mocks. A general regex-based scan of every POST form
in both templates confirms none are missing a token going forward.

## [1.0.0] - 2026-06-08

### First full release

- Dashboard: per-subnet scan status cards showing last scan time, total hosts found, rogue count
- Manual scan trigger per subnet via "Scan Now" button
- Background scanning — scan runs in a thread, page returns immediately
- Poll-based live update — scanning card auto-refreshes every 3 seconds until done
- Results page: full host list with IP, hostname, MAC, Kea status (known/rogue), filter buttons
- Rogue device alert — fires a Jen notification (all configured channels) when rogue devices are found
- nmap support (preferred) with arp-scan fallback
- Respects Jen subnet access control — restricted users only scan their assigned subnets

### Requirements

- nmap on the Jen host: `sudo apt install nmap`

## [0.1.0] - 2026-06-05

- Stub plugin for framework testing
