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

## 7.2 Attack simulators (`tools/simulate/sim.py`)

All of them are harmless. They open ordinary TCP connections to hosts you choose and hold each one for a few seconds, so the 2 s socket poll sees it. Run the engine with `--profile demo`. For S1/S2, run `sim.py sink` on a second machine, or on this one and target this machine's LAN IP (not 127.0.0.1, which is ignored).

| ID | Command | What it does | Expected |
|----|---------|--------------|----------|
| S1 | `sim.py beacon --host <sink> --port 4444 --interval 30` | Short TCP connection every 30 s ± 1 s | H2 beacon + H1 port → **High** once 6 beacons are seen (~3 min); **Medium** while still learning (beacon damped) |
| S2 | `sim.py exfil --host <sink> --port 9000 --mb 200` | One large upload | full mode: H4 (+H3 new dest) → **Medium/High**; standard mode: no alert (no byte counts) |
| S3 | `sim.py oddport --host portquiz.net --port 31337` | One connection to a backdoor port | H1 1.0 → **Low** (45) on its own |
| S4 | `sim.py office` | `%TEMP%\netsentry-sim\WINWORD.EXE` (a renamed cmd.exe) → powershell.exe → example.com:443 | H7 1.0 → **Medium** |
| S5 | `sim.py masquerade` | Renamed curl.exe at `%TEMP%\netsentry-sim\svchost.exe` downloads slowly | H7 1.0 (+H3) → **Medium** (60–67) |
| S6 | `sim.py blocklist --host portquiz.net` | Appends the host's IP to `blocklists/ips.txt`, waits for reload, connects | **High (≥ 80)**. Remove the line afterwards |
| S7 | Python `requests` from an app that normally uses SChannel (full mode) | New JA3N | H8 0.5 → contributes |
| S8 | Any new exe connecting after the system has matured | New-app rule | H3 0.5 → **None** (18), or **Low** (25) if direct-to-IP; combined with S1 → High |

Antivirus software may block S4 or S5. That is a valid result, and worth reporting.

**Synthetic scenario.** `netsentry demo` replays a 25-minute synthetic day: 12 min of normal Chrome/Teams/OneDrive traffic, then a beacon from `%TEMP%`, a 200 MB upload to a new IP, a blocklist hit and Word → PowerShell. It runs the real engine end to end, and the integration tests assert on its results.

**Measured so far (2026-10-20, standard mode, live):** S1 with `--interval 12` against a local sink opened one **Medium (53)** alert during the learning period: *"connected to …:4444 (suspicious port: Metasploit default); 7 connections … every 11.7 s ± 1.4 s (cv 0.12) (damped while learning)"*. A 75 s idle run of normal desktop use (Chrome, Teams, VS Code, …) opened no alerts.

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
4. Run S1 (`sim.py beacon`) → a High alert appears; open it and read the evidence lines.
5. Run S2 (`sim.py exfil`) → a Medium/High alert. Press **`n`** ("this is normal") and show that the next run is scored lower.
6. Run S6 (`sim.py blocklist`) → instant High.
7. Show `config/rules.yaml`: change a weight live and watch the score change.
8. Backup plan if the network is bad: `netsentry demo --speed 10` (synthetic scenario), or `netsentry replay <recording>.jsonl --speed 5`.
