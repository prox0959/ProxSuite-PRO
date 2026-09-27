# ⚡ ProxSuite PRO (Apex Edition v2.0)

**21-in-1 Native x64 Windows EDR, Live Memory Forensics, Anti-Stealer & OSINT Command Center**

🌐 **Official Product Website:** **[https://prox0959.github.io/ProxSuite-PRO/](https://prox0959.github.io/ProxSuite-PRO/)**  
⬇️ **Direct Client Download (v2.0 ZIP):** **[ProxSuitePRO_v2.0_Customer_Release.zip](https://prox0959.github.io/ProxSuite-PRO/ProxSuitePRO_v2.0_Customer_Release.zip)**  
💬 **Buy License / Request 24h Free Trial:** **[Message @prox_0959 on X (Twitter)](https://x.com/prox_0959)**

---

## 🛡️ Overview

Traditional antivirus software relies on static file signatures on disk. Modern FUD infostealers, crypto clippers, reflective DLL loaders, and Cobalt Strike/Sliver beacons execute directly in RAM or delete themselves immediately after running.

**ProxSuite PRO (Apex Edition v2.0)** is a standalone, zero-dependency x64 Windows security and forensic triage suite packing **21 specialized engines** into a single ~90 KB native executable.

---

## 🧬 21 Built-In Proprietary Engines

| # | Engine Module | Detection / Defense Capability |
|---|---|---|
| **01** | **MemGuard PRO v2.0** | Direct `ntdll.dll` syscall prologue verification (`4C 8B D1 B8`) & `comsvcs.dll` LSASS dump alert |
| **02** | **HollowHunter** | Scans `MEM_PRIVATE` RWX/WC memory pages for unbacked `MZ/PE` headers & shellcode stubs |
| **03** | **GhostTrace** | Hunts executed-and-deleted binaries across Windows Kernel BAM, Prefetch (`.pf`), and USBSTOR |
| **04** | **VaultShield** | Guards Chrome, Brave, Edge, Discord, Telegram, Exodus & Electrum vaults against Temp stealers |
| **05** | **NetSentinel** | Native `GetExtendedTcpTable` C2 port radar & LOLBIN network connection monitor |
| **06** | **OmniTriage PRO** | Audits HKCU / HKLM registry `Run` and `RunOnce` persistence entries |
| **07** | **DriverRadar (BYOVD)** | Checks loaded kernel drivers against the LOLDrivers BYOVD database & non-System32 paths |
| **08** | **AMSIShield & ETW** | Detects in-memory blinding patches on `ntdll!EtwEventWrite` and `amsi!AmsiScanBuffer` |
| **09** | **DefenderTamper Guard** | Exposes stealth Windows Defender exclusion folders and `etc\hosts` security sinkholes |
| **10** | **GhostPersist** | Hunts `Image File Execution Options (IFEO)` debugger hijacks & `Winlogon\Shell` overrides |
| **11** | **10-Point OS Hardener** | Audits & applies `RunAsPPL`, `WDigest`, Event 4104, Credential Guard, HVCI, Secure Boot, ASR & UAC |
| **12** | **TrueVerdict PRO** | Computes file Shannon Entropy (`0.00 - 8.00`) and SHA-256 to detect packers/crypters |
| **13** | **PixelTrace OSINT** | Binary EXIF parser, GPS coordinate reverse-geocoder, C2PA/AI provenance & EOF stego carver |
| **14** | **WMI Persist Hunter** | Enumerates `root\subscription` & `root\default` for fileless WMI EventConsumer backdoors |
| **15** | **NamedPipe C2 Scanner** | Hunts Cobalt Strike (`MSSE-*`, `postex_*`), Sliver (`status_*`), Havoc & Covenant named pipes |
| **16** | **Token Privilege Audit** | Exposes unexpected processes holding `SeDebugPrivilege`, `SeTcbPrivilege` or `SeLoadDriverPrivilege` |
| **17** | **COM Hijack Detector** | Scans `HKCU\Software\Classes\CLSID` `InprocServer32` overrides for unsigned/Temp DLL hijacks |
| **18** | **Browser Ext Scanner** | Audits Chrome, Edge & Brave extension manifests for stealer permissions and rogue `update_url` |
| **19** | **Memory IOC Scanner** | Scans live LOLBIN RAM for Discord webhooks, Telegram bot C2 tokens, Ngrok & PS stagers |
| **20** | **Behavioral Correlation** | Cross-correlates alerts across engines to flag multi-signal APT & stealer attack chains |
| **21** | **Ransomware Honeypot** | Deploys hidden decoy files monitored in real time + active `NtSuspendProcess` PID containment |

---

## 🔑 How to Get a License or 24-Hour Free Trial

1. Download **[ProxSuitePRO_v2.0_Customer_Release.zip](https://prox0959.github.io/ProxSuite-PRO/ProxSuitePRO_v2.0_Customer_Release.zip)** and extract it.
2. Run `ProxSuitePRO.exe` as Administrator.
3. Click **"💬 BUY LICENSE / GET 24H FREE TRIAL (X: @prox_0959)"** inside the app (or visit **[https://x.com/prox_0959](https://x.com/prox_0959)**) to request a free 24-hour evaluation key or purchase a full v2.x license.
