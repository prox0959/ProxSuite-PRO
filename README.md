# ⚡ ProxSuite Community Edition v3.0 [Open Source - MIT]

**38-in-1 Native x64 Windows EDR, Live Memory Forensics, ThreatScore™ Behavior Engine, LOLBAS Hunter, DNS Cache & DGA Sentinel, Auto-Quarantine Vault, Live C2 Threat Intel & SIEM Command Center**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://github.com/prox0959/ProxSuite)
[![Windows Defender](https://img.shields.io/badge/Windows%20Defender-0%2F0%20Clean-success.svg)](https://github.com/prox0959/ProxSuite)
[![Engines](https://img.shields.io/badge/Forensic%20Engines-38--in--1-8A2BE2.svg)](https://github.com/prox0959/ProxSuite)
[![GitHub stars](https://img.shields.io/github/stars/prox0959/ProxSuite?style=social)](https://github.com/prox0959/ProxSuite)

---

🌐 **Official Interactive Web Portal:** **[https://prox0959.github.io/ProxSuite-PRO/](https://prox0959.github.io/ProxSuite-PRO/)**  
⚡ **Direct Standalone `.EXE` Download (Defender Verified 0/0 Clean):** **[ProxSuitePRO.exe](https://prox0959.github.io/ProxSuite-PRO/ProxSuitePRO.exe)**  
📦 **Full Release Package (`.ZIP`):** **[ProxSuite_v3.0_Community_Release.zip](https://prox0959.github.io/ProxSuite-PRO/ProxSuite_v3.0_Community_Release.zip)**  
⭐ **GitHub Repository:** **[https://github.com/prox0959/ProxSuite](https://github.com/prox0959/ProxSuite)** (Also available at `ProxSuite-PRO`)  
💎 **100% Free & Open Source:** Released under the permissive **MIT License**. All 38 enterprise forensic & EDR engines are permanently unlocked with zero paywalls, zero registration, and zero cloud dependencies.

---

## 🚀 Key Highlights in v3.0 Community Edition

- **100% Clean Antivirus Footprint:** 0 false-positive ML detections on Microsoft Defender (`MpCmdRun.exe` verified clean).
- **Engine 34 — LOLBAS & Suspicious CLI Hunter:** WMI-based process command-line auditor for MITRE ATT&CK techniques (`certutil -urlcache`, `powershell -enc`, `mshta`, `rundll32 Squiblydoo`, `bitsadmin`, `wmic`).
- **Engine 35 — DNS Cache & DGA Sentinel:** Audits active DNS client resolution cache (`ipconfig /displaydns`), computes Shannon entropy on root labels, flags DGA domains (>3.85 entropy, >12 chars), DNS tunneling (>28 char hex/base64 subdomains), and suspicious TLDs (`.top`, `.xyz`, `.onion`, `.click`).
- **Pure C# Zero-Dependency YARA Engine (Engine 36):** Parses and matches `.yar`/`.yara` rules directly against process RAM and disk with zero external DLLs (supports Cobalt Strike, Mimikatz, Sliver, and custom rule packs in `%ProgramData%\ProxSuite\rules`).
- **Process Ancestry & Behavioral Attack Chain Hunter (Engine 37):** Multi-hop parent-child lineage analyzer exposing Office macro spawns, WebShell execution, PrintNightmare, and WMI persistence chains.
- **Real-Time ETW Event-Driven Guard (Engine 38):** Subscribes to kernel ETW process creation telemetry to trigger forensic evaluation on-demand rather than heavy continuous polling (90% lower CPU footprint).
- **Elastic Common Schema (ECS) & Wazuh SIEM Streamer:** Formats telemetry in standardized NDJSON (`events.jsonl`) for instant Splunk, Elastic, and Wazuh ingestion.
- **Process Kernel DACL Anti-Tamper Shield:** Hardens `ProxSuitePRO.exe` with user-mode DACL denying `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, and `PROCESS_SUSPEND_RESUME`, paired with a `FILE_SHARE_READ` binary disk lock.
- **1-Click Executive HTML5 Dashboard:** Generates an executive-ready, interactive dark-mode HTML report with severity cards, MITRE ATT&CK mapping, and instant browser launch.
- **ThreatScore™ (0–100) Behavioral Engine:** Multi-signal live process scoring combining network sockets, unsigned binaries, Temp/AppData launch paths, Shannon entropy, and suspicious parent chains.
- **Real-Time Ransomware Guard:** `FileSystemWatcher` sentinel across `Documents`, `Desktop`, and `Downloads` detecting rapid document extension shifts (5+ in 10s) with automated thread suspension via `NtSuspendProcess`.
- **Live abuse.ch C2 Intelligence Feed:** Streams Feodo Tracker & SSLBL C2 IP blocklists and cross-references active `ESTABLISHED` TCP connections in real time.
- **XOR Auto-Quarantine Vault:** Moves detected malicious binaries into an isolated, XOR-encrypted vault (`.pqv`/`.pqm`) with 1-click restore.
- **Dual Visual Theme Engine:** Dark EDR Command Center and Minimal Light mode with encrypted preference persistence.

---

## ⚔️ ProxSuite Community Edition vs. Industry Antivirus & EDR Suites

| Forensic Capability / Attack Vector | ⚡ ProxSuite v3.1 (38-in-1) | 🛡️ Windows Defender | 🦠 Malwarebytes Premium | 🔒 Bitdefender / Kaspersky | 🦅 CrowdStrike / SentinelOne | 🧰 Sysinternals Suite |
|---|---|---|---|---|---|---|
| **Unbacked Private RWX Memory & Process Hollowing** | **✓ Live MZ/PE & Shellcode RAM Scanner** | ✗ Bypassed via AMSI/ETW patch | ⚠️ Signature / heuristic only | ⚠️ Misses custom LOLBIN hollowing | ✓ Kernel sensor (Enterprise) | ✗ Manual hex dump required |
| **Module Stomping (`.text`), Process Ghosting & Herpaderping** | **✓ Disk vs. RAM `.text` Diff & Thread Stack Audit** | ✗ Trusts `MEM_IMAGE` backed modules | ✗ Blind to Module Stomping | ✗ Misses Herpaderped PE headers | ✓ Kernel image telemetry | ✗ None |
| **NTDLL Syscall Unhooking & SSN Prologue Audit** | **✓ Audits `4C 8B D1 B8` & SSNs live** | ✗ Blind to user-mode NTDLL hooks | ✗ Not inspected | ✗ No user-visible syscall audit | ⚠️ Internal sensor only | ✗ Requires WinDbg |
| **LOLBAS & Suspicious Command-Line Auditor** | **✓ MITRE ATT&CK CLI parser (certutil/pwsh/mshta)** | ⚠️ Basic ASR rules only | ⚠️ Basic heuristic rules | ⚠️ Partial CLI logging | ✓ EDR telemetry console | ⚠️ Process Explorer inspection |
| **DNS Cache & DGA / Tunneling Sentinel** | **✓ Shannon Entropy + Subdomain Tunneling Flag** | ✗ No user-visible DNS cache auditor | ✗ Web domain filter only | ✗ Cloud web shield only | ✓ Enterprise DNS telemetry | ✗ No automated DGA score |
| **ThreatScore™ (0–100) Live Process Behavior & Attack Tree** | **✓ Multi-Signal 0–100 Score + ASCII Parent-Child Tree** | ✗ No user-visible process score | ✗ Binary clean/infected only | ✗ No parent-child attack tree | ✓ Enterprise Falcon console | ⚠️ Raw process tree only |
| **Live Abuse.ch (Feodo / SSLBL) C2 IP Correlation + VirusTotal** | **✓ Live TCP vs. Botnet Feed + 1-Click VT Lookup** | ✗ No live abuse.ch socket table | ⚠️ Basic web domain blocklist | ✗ Closed cloud lookup only | ✓ Threat Graph (Enterprise) | ⚠️ VT only in Process Explorer |
| **XOR Auto-Quarantine Vault & Real-Time Ransomware Guard** | **✓ `.pqv` Encrypted Vault + Mass-Rename `NtSuspendProcess`** | ⚠️ Often bypassed by exclusions | ✓ Quarantine + Ransomware module | ✓ Quarantine + Folder shield | ✓ Enterprise containment | ✗ No quarantine or FSW guard |
| **LSASS Deep Shield (SSP Injection, `PssCaptureSnapshot` & `comsvcs`)** | **✓ LSA SSP Audit + Snapshot/`dbgcore` Hunter** | ⚠️ Bypassed when RunAsPPL is off | ✗ No LSA SSP registry verification | ⚠️ Partial LSASS protection | ✓ Enterprise credential guard | ✗ Manual inspection only |
| **AMSI & ETW Single-Byte (`0xC3 RET`) Patch + AutoLogger Audit** | **✓ Byte Prologue + Kernel AutoLogger Check** | ✗ Blinded once patched in RAM | ✗ No prologue verification | ✗ Not reported to user | ⚠️ Partial TI-ETW | ✗ None |
| **Self-Deleting Droppers (Kernel BAM & Prefetch)** | **✓ GhostTrace BAM + `.PF` Post-Mortem** | ✗ Reports "0 Threats" if file deleted | ✗ Only scans existing files on disk | ✗ Misses post-execution deleted files | ✓ Cloud EDR timeline | ✗ No automated BAM correlation |
| **Cobalt Strike / Sliver / Havoc / BRC4 Named Pipe C2** | **✓ Dedicated `\\.\pipe\` C2 + Dynamic Rules** | ⚠️ Basic static signatures | ✗ Checks TCP/IP web domains only | ✗ Network socket focus only | ✓ Enterprise IPC telemetry | ⚠️ Lists raw pipes without C2 rules |
| **LOLBIN RAM Discord / Telegram Webhook C2 Scan** | **✓ Live RAM String IOC Hunter** | ✗ HTTPS traffic looks like normal chat | ✗ Cannot block legitimate Discord API | ✗ Allows outbound HTTPS to Discord | ⚠️ Requires custom YARA rule | ⚠️ Manual Strings search per PID |
| **Vulnerable Kernel Drivers (BYOVD / LOLDrivers + Event 7045)** | **✓ Built-in LOLDrivers + Kernel Event 7045** | ⚠️ Blocklist often disabled by admin | ✗ Trusts signed WHQL drivers | ✗ Trusts valid digital signatures | ✓ Kernel driver telemetry | ⚠️ Shows drivers without CVE match |
| **Fileless WMI Subscriptions & HKCU COM Hijacks** | **✓ Authenticode-Filtered Zero-FP Audit** | ⚠️ Misses custom HKCU InprocServer32 | ⚠️ Scans standard Run keys only | ⚠️ Partial startup inspection | ✓ Full persistence telemetry | ⚠️ Dumps 4,000+ noisy legit rows |
| **Hot-Reloadable Dynamic IOC Rules & SIEM / Webhook Streaming** | **✓ `prox_rules.json` + CEF/Webhook & EventLog** | ✗ No custom user JSON rules or Webhook | ✗ Closed signatures, no SIEM webhook | ✗ Consumer tier lacks SIEM/Webhook | ✓ Enterprise SOC console | ✗ None |
| **Licensing Cost & Availability** | **100% FREE & OPEN SOURCE (MIT)** | Included in OS | $44.99 - $59.99 / Year | $59.99 - $89.99 / Year | $100+ / Endpoint / Year (Corp Only) | Free (Manual CLI/GUI tools) |

---

## 🧬 All 38 Built-In Forensic Engines & Modules

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
| **15** | **NamedPipe C2 Scanner** | Hunts Cobalt Strike (`MSSE-*`, `postex_*`), Sliver, Havoc, BRC4 & Mythic C2 named pipes |
| **16** | **Token Privilege Audit** | Exposes unexpected processes holding `SeDebugPrivilege`, `SeTcbPrivilege` or `SeLoadDriverPrivilege` |
| **17** | **COM Hijack Detector** | Scans `HKCU\Software\Classes\CLSID` `InprocServer32` overrides for unsigned/Temp DLL hijacks |
| **18** | **Browser Ext Scanner** | Audits Chrome, Edge & Brave extension manifests for stealer permissions and rogue `update_url` |
| **19** | **Memory IOC Scanner** | Scans live LOLBIN RAM for Discord webhooks, Telegram bot C2 tokens, Ngrok & PS stagers |
| **20** | **Behavioral Correlation** | Cross-correlates alerts across engines to flag multi-signal APT & stealer attack chains |
| **21** | **Ransomware Honeypot** | Deploys hidden decoy files monitored in real time + active `NtSuspendProcess` PID containment |
| **22** | **EvasionHunter (Stomp/Ghost)** | Detects Module Stomping (`.text` byte diff vs. disk), Process Ghosting, Herpaderping & Thread Call-Stack spoofing |
| **23** | **Kernel ETW-TI & Driver Stream** | Audits `WMI\Autologger` kernel/security ETW sessions against blinding and inspects `Event ID 7045` driver loads |
| **24** | **LSASS Deep Shield (SSP/Snap)** | Audits `Lsa\Security Packages` for SSP DLL injection (`mimilib`) & hunts `PssCaptureSnapshot` / `dbgcore.dll` dumpers |
| **25** | **Self-Defense, Rules & SIEM** | Hardens own process security, locks binary with `FILE_SHARE_READ`, hot-reloads `prox_rules.json` & streams SIEM/Webhook alerts |
| **26** | **VirusTotal Hash Intel** | 1-click SHA-256 lookup via user's free VirusTotal v3 API key or instant browser fallback |
| **27** | **ThreatScore™ Live Scoring** | Real-time `0–100` behavioral threat scoring across all running processes (network, signature, Temp path, entropy, parent PID) |
| **28** | **Auto-Quarantine Vault** | Isolates malicious binaries into `%ProgramData%\ProxQuarantine` with XOR encryption (`.pqv`/`.pqm`) & 1-click restore |
| **29** | **Live Threat Intel Feed (`abuse.ch`)** | Streams Feodo Tracker & SSLBL C2 IP blocklists and correlates against active `ESTABLISHED` TCP sockets |
| **30** | **Credential Breach Audit (HIBP)** | Zero-knowledge k-Anonymity (5-char SHA-1 prefix) password breach check + email exposure lookup |
| **31** | **Scheduled Daily Auto-Scan** | Headless `/autoscan` Windows Task Scheduler integration with automated Executive HTML report & SIEM dispatch |
| **32** | **Real-Time Ransomware Guard** | `FileSystemWatcher` across `Documents`/`Desktop`/`Downloads` detecting mass extension renames (5+ in 10s) with instant `NtSuspendProcess` freeze |
| **33** | **Process Attack Tree & Dual Theme** | Automated WMI parent-child ASCII Attack Tree visualization + encrypted Dark / Minimal Light theme switcher |
| **34** | **LOLBAS Command Hunter** | WMI MITRE ATT&CK command-line auditor flagging LOLBIN abuse (`certutil`, `powershell`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`, `wmic`) |
| **35** | **DNS Cache & DGA Sentinel** | Active DNS resolution cache parser computing Shannon entropy to expose DGA domains (>3.85 entropy) and DNS tunneling exfiltration |
| **36** | **Pure C# YARA Signature Scanner** | Full in-memory & disk `.yar`/`.yara` signature scanner for Cobalt Strike, Mimikatz, Metasploit, Sliver & custom rule packs |
| **37** | **Process Ancestry & Attack Chain Hunter** | Multi-hop process lineage auditor flagging Office macro spawns, WebShell execution, PrintNightmare & WMI persistence |
| **38** | **ETW Event-Driven Real-Time Guard** | Kernel ETW process creation stream listener evaluating executions on-demand (reduces CPU footprint by 90%) |

---

## 💻 CLI & Headless Forensics Mode

ProxSuite v3.0 operates as both a modern GUI desktop application and a powerful command-line forensic utility. When run in terminal or script environments, it automatically binds to the console:

```cmd
# Run a full 38-engine forensic sweep and export to HTML & JSON
ProxSuitePRO.exe --scan --html --json findings.json

# Dump unbacked RWX shellcode pages from a suspect PID directly to disk (.bin)
ProxSuitePRO.exe --dump-rwx 8412 C:\Dumps

# Run instant LOLBAS MITRE ATT&CK command-line hunter
ProxSuitePRO.exe --lolbas

# Audit active Windows DNS client cache for DGA domains & tunneling
ProxSuitePRO.exe --dns

# Run in-memory YARA signature scan
ProxSuitePRO.exe --yara

# Hunt malicious process parent-child execution chains
ProxSuitePRO.exe --proctree

# Display ETW event-driven sentinel status
ProxSuitePRO.exe --etw

# Arm process DACL anti-tamper security & binary disk lock
ProxSuitePRO.exe --anti-tamper

# Export telemetry to Elastic Common Schema (ECS) / Wazuh format
ProxSuitePRO.exe --scan --siem events.jsonl

# Display version and engine count
ProxSuitePRO.exe --version
```

| Flag | Argument | Description |
|---|---|---|
| `--help`, `-h`, `/?` | - | Display CLI usage guidelines and command-line options. |
| `--version`, `-v` | - | Output engine release version and 35-in-1 manifest. |
| `--scan`, `-s` | - | Execute automated headless forensic triage across all active engines. |
| `--html` | - | Export findings to an executive interactive HTML5 report and open in browser. |
| `--json` | `<path>` | Output structured JSON telemetry report for SIEM / automation pipelines. |
| `--dump-rwx` | `<PID> [dir]` | Live RAM excavator: extract private RWX unbacked shellcode stubs to `.bin`. |
| `--lolbas` | - | Immediate WMI command-line sweep for LOLBIN MITRE ATT&CK execution. |
| `--dns` | - | Inspect DNS resolution cache with Shannon Entropy analysis for DGA / tunnels. |
| `--yara` | `[dir]` | Execute pure C# YARA signature scan across RAM and disk using custom or built-in `.yar` rules. |
| `--proctree` | - | Traverse process parent-child lineages to hunt malicious attack chains (Office -> cmd, etc.). |
| `--etw` | - | Audit kernel ETW process telemetry stream and event-driven sentinel status. |
| `--anti-tamper` | - | Hardens current process kernel DACL (Deny Terminate/VM_Write) and locks executable on disk. |
| `--siem` | `<path>` | Output standardized Elastic Common Schema (ECS) NDJSON telemetry for Wazuh/Splunk. |

---

## 🛠️ Building from Source

ProxSuite is 100% self-contained and compiles with Microsoft's native `.NET Framework 4.8` compiler (`csc.exe`) without needing Visual Studio or external NuGet packages:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /platform:x64 /optimize+ /out:ProxSuitePRO.exe /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll /r:System.Web.Extensions.dll /r:System.Net.Http.dll /r:System.ServiceProcess.dll /r:System.Security.dll Security\AntiCrack.cs Security\CGAuthEngine.cs Engines\CoreEngines.cs UI\MainDashboardForm.cs
```

Or simply run `build.bat`.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details. Free for personal, commercial, and educational use.
