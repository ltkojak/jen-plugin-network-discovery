# Network Discovery Plugin — Changelog

## [1.2.1] - 2026-09-26

Requires Jen 5.57.0 or later, unchanged. No behaviour change.

### Changed

- The two statistics tiles (the last scan's rogue count, and the results page's per-status counts) carried a style attribute each, because their colour depends on the value. The colour is now a class chosen by the same condition, so no template carries an inline `style=` attribute, and `tools/verify.py` now fails one that does (the round-4 UI rule, already enforced in the other bundled plugins).
- This plugin already logged database and scan failures and showed a generic message, so it needed no change for the error-text rule Jen now tests in every bundled plugin.

## [1.2.0] - 2026-09-23

### Sprite icons, a rowlist results table, a Timeline event per new unknown, and a search provider — built on Jen's plugin API v3

Every emoji in the two pages — including the seven `_STATUSES` labels —
is now a sprite icon via Jen's own `icon()` global, and the 60 inline
`style="…"` attributes are gone, moved into named classes in a
page-local `<style>` block, the same convention `jen-plugin-ipam`
1.6.0 uses. The results table is now a `rowlist` with `data-m` on
every cell.

Two changes to how a new unknown host is reported. It now also
`emit`s a `discovery.unknown` event — a kind core Jen has reserved for
this plugin since Q43 — so it shows up on the Timeline and in Client
Investigation, not only in an alert channel. And the alert itself
moves off Jen core's hard-coded `rogue_device` type onto one this
plugin registers for itself, `network-discovery_rogue_device` (still
labelled "Rogue Device", same icon, same message shape) — `rogue_device`
stays in Jen core as a legacy entry so an install whose channels
already opted into it keeps working, but this plugin no longer sends
under it.

Last: discovered hosts are now in Jen's global search by MAC, IP,
hostname, label or vendor, showing when they were last seen and
linking straight to that subnet's results.

Requires Jen 5.57.0 (plugin API v3) — the `emit`, `register_alert_type`
and search-provider hooks all shipped there.

## [1.1.2] - 2026-09-23

### Viewers were never actually read-only, and two clicks could queue the same subnet twice

Jen's viewer tier is read-only everywhere else, but Network Discovery's
`start_scan` and `mark_known` routes checked only subnet access, never
the role. A read-only viewer could launch an nmap sweep from the Jen
host, and — since the known-hosts list has no subnet column by design
(a MAC is a MAC, wherever it's seen) — could add or forget an entry
and silence or un-silence the `rogue_device` alert for a MAC on any
subnet, not just their own. Both routes now refuse a viewer up front,
before either one even looks at the subnet or the submitted form, with
a plain "Viewers can look at Discovery but not scan or mark hosts."
Known hosts stay global by design; the README says so.

Separately, a scan's `nd_scan_jobs` row only appeared once the scan
thread actually acquired the shared scan lock and started running —
not when it was requested. Two clicks on different subnets while one
scan held the lock could queue two duplicate scans of the second
subnet, since neither saw the other's job row yet. A scan is now
recorded as `queued` the moment it's requested (by a click or the
scheduler), before the lock is even reached, and moves to `running`
once it actually starts; the duplicate check and the scheduler both
treat a queued scan the same as a running one, and the index card
shows "Queued" while it waits its turn.

## [1.1.1] - 2026-09-15

### Imports only `jen.plugin_api`

Jen 5.34.0 introduces one import surface for plugins, `jen.plugin_api`
— a versioned re-export of what plugins have needed so far, so a rename
inside Jen can never silently break a plugin again. Network Discovery
now imports from it and nowhere else inside `jen` (`installed_plugins()`
replaces the internal `discover_plugins`, `subnet_map()` replaces
`extensions.SUBNET_MAP`), and its manifest declares `"plugin_api": 1`.
No functional change. **Requires Jen 5.34.0 or later** (a 5.34.0 beta
counts).

## [1.1.0] - 2026-09-13

### Every host gets a name for what it is — "rogue" meant "not in Kea"

Until now a found host was either "in Kea" (an active lease or a
reservation *for this subnet*) or "rogue". That flagged the gateway,
the DNS servers, the Kea server itself, the Jen host, every device
with a global reservation, every static host recorded in IPAM Lite,
and every device Jen had ever seen but which had no lease at that
moment. The maintainer's first scan reported the gateway as rogue.

Each host now gets one status, first match wins:

| status | means |
|---|---|
| `lease` | an active Kea lease, by IP or by MAC |
| `reservation` | a Kea host reservation — this subnet's **or a global one** (v1.0.x matched only `dhcp4_subnet_id = this subnet`) |
| `infrastructure` | the gateway, a DNS server, the Kea server, the Jen host, network/broadcast — from Jen's subnet context |
| `ipam` | an IPAM Lite static/planned entry for the IP or MAC, when that plugin is installed |
| `device` | a device Jen has seen before (the devices table, by MAC) with no lease right now — a static host |
| `known` | marked "I know this one" on the results page |
| `unknown` | nothing above — the only status that alerts |

Vendor and device type come from Jen's OUI table (and the devices
table where Jen already classified the MAC). The results page filters
by status, shows a label (the IPAM label, the device name, "Gateway"),
and offers per-host actions: **👍 Known** (with a note; never alerts
again — **Forget** reverses it), **📌** create a Kea reservation with
IP/MAC/hostname prefilled, **📋** add an IPAM Lite entry for the
address (when IPAM Lite v1.5.0+ is installed). The old `in_kea` /
`rogue` columns are kept and derived (rogue = unknown).

**Requires Jen 5.30.0** for the subnet context, the periodic-job hook
and the shared CSV guard.

### Install nmap from Jen

The manifest declares `os_packages: ["nmap"]`. On a systemd host the
"nmap not found" notice — here and on Settings → Plugins — is now an
**Install nmap** button that goes through Jen's root-run plugin
service (the same request/execute split as plugin installs; the root
side only ever installs packages on its own allowlist). Elsewhere the
`apt install` command stays.

### Alerts key on the MAC

"New unknowns" were compared by IP, so a DHCP client that hopped
addresses re-alerted on every scan. The comparison is by MAC when the
scan captured one (IP otherwise), and the alert lists hostname, vendor
and MAC per host instead of bare IPs.

### Scheduled scans

Per subnet, superadmin: scan every 6 / 12 / 24 hours or weekly (off by
default), through Jen's periodic-job hook — no thread of the plugin's
own. A scheduled run is a normal job: same results, same pruning, same
alert rule.

### Scope, time, and what went wrong

- A subnet larger than a /20 is refused with a reason instead of
  timing out; the nmap timeout scales with the subnet (a /24 gets
  ~90 s, a /20 the cap).
- A failed scan records *why* (`nd_scan_jobs.error`) and the page shows
  it — "nmap did not finish within 92s", "interrupted (Jen restarted
  mid-scan)" — instead of a bare ✗.
- The results page shows what changed since the previous scan
  (+appeared / −gone, keyed by MAC), and exports the scan as CSV (every
  cell formula-guarded).

### Housekeeping

- Migrations 3–9 (plain portable DDL): `status`, `label`, `vendor`,
  `device_type` on results; `error` on jobs; `nd_known_hosts`;
  `nd_settings`.
- `tools/test_plugin.py`: pure-function checks (classification
  precedence, MAC-keyed deltas, parsers, scope/timeout, scheduling) run
  in CI after `verify.py`.
- A running job is considered abandoned after 30 minutes (was 10 — a
  /20 legitimately takes longer now).

## [1.0.7] - 2026-09-13

### Housekeeping: no dynamically-built SQL in the prune

v1.0.2's prune deleted old jobs with a `WHERE id IN (%s,%s,…)` whose
placeholder list was built at runtime — parameterised and safe, but
string-built SQL is exactly what Jen's bandit gate (which scans the
bundled copy of this plugin) flags. It now deletes each old job with a
fixed, fully parameterised statement instead; there are at most a
handful per scan. No functional change.

## [1.0.6] - 2026-09-13

### Housekeeping: the IPv4-only README note, back from the bundled copy

Jen v5.0's IPv6 rollout added an "IPv4 only" scope note to this
plugin's README — but only in the copy bundled inside `jen-kea`; the
v1.0.3 README rewrite here didn't carry it, and Jen's own test suite
checks for it. Restored. No functional change.

## [1.0.5] - 2026-09-13

### Housekeeping: same lint rules as Jen

Jen bundles a byte-for-byte copy of this plugin under
`jen-kea/plugins/network-discovery/` and lints its whole tree in CI
with its own, stricter ruff configuration (`ruff check .` and `ruff
format --check .`). This repo's `ruff.toml` is now identical to Jen's,
ruff is pinned to the same version in CI, and `plugin.py` is
reformatted to match — so a resync into Jen can never fail Jen's lint.
Mechanical only: import ordering and formatting. No functional change.

## [1.0.4] - 2026-09-13

### Housekeeping: explicit migration versions

`db_migrations` now uses Jen's explicit `{version, description, sql}`
format instead of the flat positional list (both plugins are on it as
of today). Versions 1 and 2 are exactly the old positions 1 and 2, so
an existing install runs nothing new. No code or schema changes.

## [1.0.3] - 2026-09-13

### Scans now find every host on an attached subnet, with MACs

Jen runs as an unprivileged service user, so `nmap -sn` can't send raw
packets: it degrades to TCP connect() probes against ports 80 and 443
and never reports a MAC. In practice that meant a scan found only the
devices with a web server on them and matched them against Kea by IP
alone — so a device whose lease IP had changed was flagged rogue on
every scan, and most IoT/embedded devices weren't found at all.

The sweep now probes a wider set of ports (22, 80, 443, 445, 3389,
8080, 8443, 9100) and, more usefully, reads the kernel neighbour
table (`ip -4 neigh`) right after it. Every connect() attempt makes
the kernel ARP for its target first, and every host that exists
answers ARP whether or not it answers TCP — so on a subnet the Jen
host is directly attached to, the table holds a fresh REACHABLE entry,
with MAC, for every live host. Those are merged in: REACHABLE entries
inside the CIDR become found hosts even when nmap saw nothing, and any
non-failed entry supplies the MAC for a host nmap did see (a STALE
entry alone never adds a host — it can outlive the device by hours).
On a routed subnet there are no entries and behaviour is unchanged.
With MACs available, the Kea cross-reference works the way v1.0.1
intended.

### Removed: the arp-scan fallback

It could never have worked: `arp-scan --localnet <cidr>` is a usage
error (`--localnet` and a target are mutually exclusive), and arp-scan
needs raw sockets the service user doesn't have. When nmap was absent
it produced a "done" scan with zero hosts rather than an error. nmap
is now simply required, and the page says so.

### Alerts fire for *new* unknowns, not every unknown on every scan

The manifest has always said "alerts on new unknowns", but every scan
alerted on every rogue it found — a permanently unmanaged device paged
on each run. The alert now lists only rogue IPs the previous completed
scan of that subnet hadn't already flagged (a first scan reports all
of them), and passes `subnet_id` so a subnet-scoped alert channel
filters it like any other per-subnet alert.

### Fix: a scan interrupted by a Jen restart stayed "Scanning…" forever

The scan runs in a background thread; if Jen restarted mid-scan the
job stayed `running` with nothing left to finish it, the index page
showed "⏳ Scanning…" indefinitely, and the poller reloaded every three
seconds for good. A `running` job older than ten minutes is now marked
`error` on the next page load or scan request. A second scan of a
subnet that genuinely is mid-scan is refused with a message instead of
being queued silently behind the first.

### Smaller fixes

- A Kea reservation's `dhcp_identifier` was treated as a MAC whatever
  its type; only a type-0 (hw-address) identifier is one now, so a
  6-byte client-id can't accidentally match a scanned MAC.
- `results` and the scan-status endpoint no longer surface raw
  exception text; they log it and show a generic message.
- Dropped the in-tree `.enabled` marker — Jen has kept its enable
  marker outside the plugin directory since v5.13.0 — and rewrote the
  README's install instructions, which still described that marker
  and a path Jen no longer installs to.

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
