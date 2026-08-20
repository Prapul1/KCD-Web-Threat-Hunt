# 📦 Indicators of Compromise (IOCs) — KCD-Web

## Network IOCs

| IP Address | Port | Classification |
|---|---|---|
| 45.227.254.151 | 3389 | Attacker RDP source |
| 45.227.254.156 | 3389 | Attacker RDP source |
| 79.127.147.207 | 3389 | Attacker RDP source |
| 82.147.85.6 | 80 | Staging / download server |
| 185.213.157.164 | 10066 | Primary C2 |
| 178.248.233.33 | 80 | C2 / beaconing |
| 185.180.201.1 | 80 | C2 / beaconing |
| 89.221.239.1 | 80 | C2 / beaconing |
| 90.156.232.4 | 80 | C2 / beaconing |
| 93.186.225.194 | 80 | C2 / beaconing |
| 87.240.132.67 | 80 | C2 / beaconing |
| 87.240.132.72 | 80 | C2 / beaconing |
| 87.240.132.78 | 80 | C2 / beaconing |
| 87.240.129.133 | 80 | C2 / beaconing |
| 87.240.137.164 | 80 | C2 / beaconing |

## File Hashes (SHA256)

| File | SHA256 |
|---|---|
| `svchost.exe` (ServiceEx) | `9BD14131C0629461D045712A78F5ADFE64947C922577C924694A9B122BE28E70` |
| `wahiver.exe` | `AF60E17891BE5F4E6A777056F539B9ACFC4C695F7D781E131FD3F795EF0A60B9` |
| `wasp.exe` | `666959817A5A277B546DAD23B5317758AA6262FAC713A18267584B8105E86443` |

## File Paths

| Path | Description |
|---|---|
| `C:\Windows\p2.exe` | Stage 1 dropper |
| `C:\Windows\deb.exe` | Stage 2 dropper |
| `C:\Windows\ww.exe` | Stage 3 dropper |
| `C:\Windows\b1.exe` | SFX archive (Java + brute tools) |
| `C:\Windows\fonts\b\u.exe` | SFX archive (AlwaysUp) |
| `C:\Windows\Fonts\w\svchost.exe` | Fake service binary (ServiceEx) |
| `C:\Windows\Fonts\w\go.bat` | Service installation script |
| `C:\Windows\Fonts\w\wa\wahiver.exe` | Malware loader |
| `C:\Windows\Fonts\w\wa\wasp.exe` | Infostealer payload |
| `C:\Windows\Fonts\w\wa\waspwing.exe` | Headless browser renderer |
| `C:\Windows\Fonts\w\wa\plc\*.dll` | Fake Chromium plugins |
| `C:\Windows\Fonts\w\wa\Temp\*` | Data staging directory |
| `C:\Windows\Fonts\b\brute.properties` | Brute-force config |
| `C:\Windows\Fonts\b\lib\jre1.8.0_162\*` | Portable Java runtime |
| `C:\Windows\Fonts\u\AlwaysUpService.exe` | Persistence tool |
| `C:\Windows\debug\go.bat` | Backup persistence script |
| `C:\Windows\Fonts\init\go.bat` | Backup persistence script |

## Registry / Service

| Key | Value |
|---|---|
| `HKLM\System\CurrentControlSet\Services\WindowsDefend` | Malicious service |
| `...\WindowsDefend\Parameters\Application` | `C:\windows\fonts\w\wa\wahiver.exe` |
| `...\WindowsDefend\Parameters\AppDirectory` | `C:\windows\fonts\w\wa` |

## Compromised Accounts

| Account | Context |
|---|---|
| `KCD-Web\ftp$` | Primary attack account (FTP service abused) |
| `KCD-Web\administrator` | Interactive RDP session observed |
