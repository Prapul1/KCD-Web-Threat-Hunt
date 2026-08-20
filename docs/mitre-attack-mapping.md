# 🛡️ MITRE ATT&CK Mapping — KCD-Web Compromise

| Technique ID | Technique Name | Evidence |
|---|---|---|
| T1133 | External Remote Services | RDP access from `45.227.254.x` |
| T1059.001 | PowerShell | Interactive payload download from `82.147.85.6` |
| T1059.003 | Windows Command Shell | `cmd.exe /c go.bat` |
| T1105 | Ingress Tool Transfer | SFX archives, PowerShell download |
| T1036 | Masquerading | `svchost.exe` in Fonts folder, service named `WindowsDefend` |
| T1574.002 | DLL Side-Loading | Unsigned ServiceEx binary |
| T1543.003 | Windows Service | `WindowsDefend` service creation |
| T1574.010 | Services File Permissions Weakness | File drops in Fonts directory |
| T1562.001 | Disable or Modify Tools | Killed `sysdiag`, `hrwfpdrv`, `taskmgr` |
| T1053 | Scheduled Task/Job | AlwaysUp service persistence |
| T1071.001 | Web Protocols (C2) | HTTP beaconing on port 80 |
| T1571 | Non-Standard Port (C2) | Port 10066 to `185.213.157.164` |
| T1027 | Obfuscated Files | IMPHASH all zeros (packed `wahiver.exe`) |
| T1055 | Process Injection | Chromium renderer abuse (`waspwing.exe`) |
| T1021 | Remote Services | Sysmon `RuleName` tagging on external connections (`technique_id=T1021`) |
