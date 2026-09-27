# Meraki Health Bot

Read-only health checks, quiet monitoring, and weekly digests for a Cisco Meraki network, built for a Grok Bot that uses the Meraki Dashboard API v1.

It gives you a plain-English report with a number behind every finding (Wi-Fi quality, WAN loss and latency, firewall and VLAN exposure, firmware, licenses, alerting gaps), and each finding tells you the Dashboard setting that fixes it. After that it watches the network and only speaks up when something new breaks or clears.

## What you need
- A Meraki organization with at least one network (MX, MR, MS, MV, or MT in any mix).
- A Dashboard API key, ideally from a read-only org admin, with Dashboard API access enabled under Organization > Settings.
- Python 3 (standard library only).

## Files
- `bin/mclient.py`: a client that only makes GET requests. It's rate-limited, backs off on 429, and never prints the key.
- `bin/setup.py`: picks the org and network and records a baseline.
- `bin/check.py --mode full|monitor|weekly`: runs the checks and writes JSON findings plus state.

The key is read from `MERAKI_API_KEY`. Nothing in this repo writes to your network.

## Install on a Grok Bot box
```
mkdir -p /workspace/meraki/bin && cd /workspace/meraki/bin
for f in mclient.py setup.py check.py; do curl -fsSLO https://raw.githubusercontent.com/Presidio-Federal/Meraki-health-bot/main/bin/$f; done
```
