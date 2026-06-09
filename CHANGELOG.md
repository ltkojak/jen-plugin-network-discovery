# Network Discovery Plugin — Changelog

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
