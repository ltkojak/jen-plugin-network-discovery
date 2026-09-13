# Network Discovery Plugin — Changelog

## [1.0.2] - 2026-09-13

### Fix: every successful scan was recorded as an error

After a scan found hosts, the job pruned older results with a single
`DELETE … WHERE job_id IN (SELECT id FROM nd_scan_jobs … ORDER BY
started_at DESC LIMIT 100)`. MySQL and MariaDB both reject a `LIMIT`
inside an `IN` subquery ("This version … doesn't yet support 'LIMIT &
IN/ALL/ANY/SOME subquery'"), so the statement raised right after the
job row was created — the job was marked `error`, no results were
stored, and the page showed "✗ Error" for a scan that had actually
completed. The same code was in the bundled copy inside `jen-kea`, so
diffing against it (how v1.0.1's bugs were found) couldn't have caught
this one. The prune now picks the job ids in Python and deletes by
explicit list, and actually does what the old comment said: keep the
newest 3 jobs per subnet (including this one), dropping older jobs
and their results rather than results only.

The scan's error path also closed the DB connection and then closed it
again in `finally`; harmless on Jen's pooled connections, an exception
on the raw-connection fallback. Removed the extra close.

### Fix: Content-Security-Policy compatibility (no inline scripts)

Jen v5.22.0 dropped `'unsafe-inline'` from its script-src CSP — every
`<script>` needs a per-request nonce and inline `onclick=` attributes
are never executed. The three filter buttons on the results page were
`onclick=` handlers (so filtering silently did nothing), and both
`<script>` blocks (the results filter, the per-subnet scan-progress
poller on the index page) were un-nonce'd — the poller not running is
why an in-progress scan never refreshed on its own. The buttons now
carry `data-filter-mode` and one delegated click listener, and both
scripts carry `nonce="{{ csp_nonce }}"`. This matches the copy bundled
in `jen-kea` since v5.22.0, which also gained the "IPv4 subnets only"
note shown when Jen's IPv6 support is enabled — brought over here too.

### Housekeeping

- Blueprint gets an explicit `root_path` (as the bundled copy and IPAM
  Lite already do), so templates resolve wherever Jen loads the plugin
  from — including the root-owned `/opt/jen/plugins-installed/` tree
  a v5.27.0+ install lands in.
- Dropped unused imports (`json`, `datetime`, `request`,
  `current_user`).
- `manifest.json`'s `changelog_url` pointed at the copy of this file
  bundled inside `jen-kea`; it now points at this repo's own.
- New CI (`.github/workflows/verify.yml`, `tools/verify.py`): every
  push and tag checks that `plugin.zip` is byte-for-byte a rebuild of
  the tree, that no template has an inline handler or un-nonce'd
  script, that the manifest version matches this file's top entry,
  and that `plugin.py` compiles and passes ruff. `.gitattributes` pins
  LF so the zip is built identically on any platform; build it with
  `python3 tools/verify.py --build`.

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
