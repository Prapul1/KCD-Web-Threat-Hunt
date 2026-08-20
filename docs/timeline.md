# 🗺️ Attack Timeline — KCD-Web

All times UTC.

| Time | Phase | Actor / Process | Action |
|---|---|---|---|
| Apr 05, 10:40 | C2 Beaconing | `wahiver.exe` | Early beaconing to `178.248.233.33` |
| Apr 08, 03:18 | Initial Access | `administrator` | Interactive RDP session, opens PowerShell |
| Apr 08, 03:22 | Initial Access | `ftp$` | Interactive RDP session, opens PowerShell |
| Apr 08, 03:22 | Download | `powershell.exe` | Downloads payload from `82.147.85.6:80` |
| Apr 08, 03:23 | Staging | `p2.exe` | Drops `C:\Windows\Fonts\init\go.bat` |
| Apr 08, 03:24 | Staging | `deb.exe` | Drops `C:\Windows\debug\go.bat` |
| Apr 08, 03:24 | Staging | `ww.exe` | Drops `C:\Windows\Fonts\w\go.bat` |
| Apr 08, 03:24 | Execution | `cmd.exe` → `go.bat` | Runs `svchost install WindowsDefend` |
| Apr 08, 03:24 | Persistence | `svchost.exe` (`ftp$`) | Creates `HKLM\...\Services\WindowsDefend` → `wahiver.exe` |
| Apr 08, 03:24 | Privilege Escalation | `services.exe` (SYSTEM) | Launches `svchost.exe run` → `wahiver.exe` |
| Apr 08, 03:24 | C2 | `wahiver.exe` | Connects to `185.213.157.164:10066` |
| Apr 08, 03:24 | Defense Evasion | `ftp$` via `cmd` | Kills `taskmgr`, stops/deletes `sysdiag` & `hrwfpdrv` |
| Apr 08, 03:59 | Staging | `b1.exe`, `u.exe` | Extracts SFX archives (Java JRE, brute tools, AlwaysUp) |
| Apr 08, 08:54 | Execution | `wahiver.exe` → `wasp.exe` | Launches infostealer with headless browser farm |
| Apr 08, 08:54 | Staging | `wasp.exe` | Drops data to `C:\Windows\Fonts\w\wa\Temp\` |
| Apr 08, 08:54+ | C2 | `wahiver.exe` | Continuous beaconing to multiple external IPs on port 80 |

**Total observed dwell time:** ≥ 3 days (first C2 beacon April 5 → discovery/analysis April 8).
