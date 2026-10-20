# 7. Validation Plan

The aim is to show that the mechanism works and to report its false positives honestly, not to claim perfect detection.

## 7.1 Capture correctness

| ID | Check | Method | Pass criterion |
|----|-------|--------|----------------|
| V1 | Attribution | Open two known sites in a browser, then compare `netsentry capture --dump` with `netstat -ano` and Resource Monitor → Network | Every established TCP connection has the same PID in both |
| V2 | Byte accuracy (full mode) | Download a known 100 MB file, then upload a 50 MB file with `curl` | `bytes_in` / `bytes_out` within ±10 % |
| V3 | Domain coverage | 10 minutes of normal browsing | ≥ 90 % of browser flows have a domain. The rest are listed with their reason (QUIC, no rDNS) |
| V4 | Degradation | Run without admin | Standard mode is shown in the UI, H4/H8 show as `n/a`, and nothing crashes |
| V5 | Tick budget | Replay a busy 1-hour recording at 50× | p95 tick < 250 ms |

## 7.2 Attack simulators (`tools/simulate/`)

All of them are harmless and only talk to endpoints we control or to public test services. Run with `--profile demo`.

| ID | Simulator | What it does | Expected |
|----|-----------|--------------|----------|
| S1 | `beacon.py --interval 30 --port 4444 --host <test VPS or LAN box>` | Opens a short TCP connection every 30 s ± 1 s | H2 beacon + H1 port → **High** within ~3.5 min (6 beacons) |
| S2 | `exfil.py --mb 200 --to http://<LAN box>:8000/upload` | Single large POST | H4 (+H3 if new dest) → **Medium/High**; with an idle simulation → High |
| S3 | `odd_port.py --host portquiz.net --port 31337` | One connection to an unusual port | H1 1.0 → **Low/Medium** (45 alone; higher with H3) |
| S4 | `lolbin.ps1` started from an Office macro-free stand-in (`python -m tools.simulate.fake_parent winword.exe powershell ...`) | Child script host connects out under a parent named like Office | H7 → **Medium** |
| S5 | Copy `curl.exe` to `%TEMP%\svchost.exe` and fetch a page | Masquerading + staging path | H7 1.0 (+H3) → **Medium** (60–67) |
| S6 | Add a test IP to `blocklists/ips.txt`, then connect to it | Blocklist | **High (≥ 80)** on the next tick |
| S7 | Python `requests` from an app that normally uses SChannel (full mode) | New JA3N | H8 0.5 → contributes |
| S8 | New unknown exe connects after the system has matured | New-app rule | H3 0.5 → **None** (18), or **Low** (25) if direct-to-IP; combined with S1 → High |

## 7.3 False-positive study

Run NetSentry on a normal day (≥ 6 h, default profile, after the 24 h learning period). Record:

| Metric | Source |
|--------|--------|
| Alerts per hour by severity | `alerts` |
| % marked "this is normal" | `user_actions` |
| Top false-positive causes (expected: cloud sync, updaters, game launchers, Teams/Slack) | manual labelling of each alert |
| Effect of feedback: FP rate in hours 1–3 vs 4–6 | `alerts` + `user_actions` |

Report it as a table of true and false positives across the simulator runs plus the normal-day run, and include **at least two real false positives** with the reason each one fired. Each should also show what the feedback loop did about it.

## 7.4 Demo script (≈ 10 min)

1. `netsentry doctor` → full mode, Npcap OK.
2. `netsentry run --profile demo` → the live table fills; point out the per-app attribution and the learning countdown.
3. Open the detail view for `chrome.exe`: parent chain, destinations, bytes, JA3N.
4. Run S1 (beacon) → a High alert appears; open it and read the evidence lines.
5. Run S2 (exfil) → a Medium/High alert. Mark it **"this is normal"** and show that the next run is scored lower.
6. Run S6 (blocklist) → instant High.
7. Show `config/rules.yaml`: change a weight live and watch the score change.
8. Backup plan if the network is bad: `netsentry replay demo.jsonl --speed 5`.
