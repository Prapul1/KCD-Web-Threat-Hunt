# 🔍 KCD-Web Threat Hunt — Sysmon Log Analysis in Splunk Cloud

A full threat-hunting investigation into a compromised Windows host (`KCD-Web`, `172.16.1.7`), performed entirely in **Splunk Cloud** against a **Sysmon CSV export**. The investigation traces the attacker from initial RDP brute-force access through dropper staging, fake-service persistence, C2 beaconing, defense evasion, and a headless-browser credential farm.

> This repo documents the exact SPL queries run, the reasoning behind each pivot, and the corresponding Splunk screenshots — reconstructed step by step so the methodology can be reused on future hunts.

---

## 📌 TL;DR

| | |
|---|---|
| **Victim host** | `KCD-Web` (`172.16.1.7`) |
| **Log source** | Sysmon (`Microsoft-Windows-Sysmon/Operational`), exported to CSV |
| **Platform** | Splunk Cloud (`index=main`, `sourcetype=csv`) |
| **Root cause** | RDP brute force → interactive PowerShell download → multi-stage dropper chain |
| **Persistence** | Fake Windows service `WindowsDefend` (typosquat of Windows Defender) |
| **Payload** | `wasp.exe` infostealer + `waspwing.exe` headless Chromium browser farm |
| **C2** | `185.213.157.164:10066` (primary), plus HTTP beacons to ~10 external IPs |
| **Confirmed malicious** | `wasp.exe` (38/71 VT), `svchost.exe`/ServiceE (16/71 VT) |

Full write-up: **[docs/investigation-report.md](docs/investigation-report.md)**

---

## ⚠️ A note on data ingestion (read this first)

The raw Sysmon export (`KCD.csv-2026-4-8 14.52.1.csv`) was **too large to upload directly through the Splunk Cloud web UI** ("Add Data" → file upload has practical size limits and times out / rejects large single-file uploads).

To get the data into the `main` index, a **Splunk Universal Forwarder** was used instead:

1. Installed the Universal Forwarder on the machine hosting the CSV export.
2. Configured `inputs.conf` to monitor the folder/file containing the CSV and forward it to the Splunk Cloud indexers (via the provided HEC/forwarder receiving port, using the deployment/validation cert package from the Splunk Cloud instance).
3. Set `sourcetype=csv` on ingestion and let the forwarder stream the file in, rather than pushing it through the browser-based upload path.
4. Verified ingestion completeness with `index="main" source="G:\\KCD.csv-2026-4-8 14.52.1.csv" | stats count`, then began the investigation described below.

This is why every query in this repo references the exact CSV path as `source=` — it's the literal monitored file path from the forwarder's `inputs.conf`, not an uploaded filename.

**Takeaway:** for large one-off CSV/log dumps that exceed the UI upload limit, use a Universal Forwarder (or HEC) instead of the web upload flow.

---

## 🗂️ Repo structure

```
KCD-Web-Threat-Hunt/
├── README.md                          ← you are here
├── docs/
│   ├── data-ingestion.md              ← why/how a Universal Forwarder was used (CSV too large for web upload)
│   ├── investigation-report.md        ← full phase-by-phase writeup with embedded screenshots
│   ├── timeline.md                    ← consolidated attack timeline
│   ├── ioc-list.md                    ← all IPs, hashes, file paths, accounts
│   └── mitre-attack-mapping.md        ← MITRE ATT&CK technique mapping
├── spl-queries/
│   └── all-queries.spl                ← every SPL query used, in order, commented
└── screenshots/
    ├── 01-baseline-triage/
    ├── 02-noise-filtering/
    ├── 03-wasp-discovery/
    ├── 04-wahiver-parent/
    ├── 05-persistence/
    ├── 06-execution-chain/
    └── 07-initial-access-lateral-movement/
```

---

## 🧭 Investigation phases

1. **[Baseline triage](docs/investigation-report.md#phase-1--initial-data-exploration--baseline-understanding)** — EventCode distribution, DestinationIp distribution, understanding what's "normal" before hunting.
2. **[Noise filtering](docs/investigation-report.md#phase-2--noise-filtering--internalexternal-classification)** — excluding internal/loopback traffic, CIDR-based tagging.
3. **[wasp.exe discovery](docs/investigation-report.md#phase-3--malware-discovery--waspexe)** — the infostealer payload, confirmed malicious via VirusTotal.
4. **[wahiver.exe parent investigation](docs/investigation-report.md#phase-4--parent-process-investigation--wahiverexe)** — the loader, its C2 traffic, and loopback IPC.
5. **[Persistence](docs/investigation-report.md#phase-5--persistence-mechanism-discovery)** — the fake `WindowsDefend` service.
6. **[Execution chain reconstruction](docs/investigation-report.md#phase-6--full-execution-chain-reconstruction)** — droppers, SFX archives, service installer.
7. **[Initial access & lateral movement](docs/investigation-report.md#phase-7--initial-access--lateral-movement)** — RDP brute force, PowerShell download.
8. **[Defense evasion](docs/investigation-report.md#phase-8--defense-evasion-discovery)** — AV/task manager kill commands.
9. **[Payload analysis](docs/investigation-report.md#phase-9--payload-analysis--waspwingexe-browser-farm)** — headless Chromium browser farm.

---

## 🛡️ MITRE ATT&CK coverage

See **[docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md)** for the full table (T1133, T1059, T1105, T1036, T1574, T1543, T1562, T1071, T1571, T1027, T1055, and more).

## 📦 Indicators of Compromise

See **[docs/ioc-list.md](docs/ioc-list.md)** for the full IP/hash/path/account list.

## 🕒 Attack timeline

See **[docs/timeline.md](docs/timeline.md)**.

---

## Disclaimer

This repository is for defensive threat-hunting/education/portfolio purposes. IOCs are shared to support blocking and detection; no malware binaries are included, only Sysmon telemetry and analysis.
