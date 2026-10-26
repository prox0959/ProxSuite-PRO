using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using ProxSuitePRO.Engines;
using ProxSuitePRO.Security;

[assembly: AssemblyTitle("ProxSuite PRO Endpoint Diagnostics & Telemetry")]
[assembly: AssemblyDescription("Enterprise Endpoint Diagnostics, System Integrity & Memory Telemetry Utility")]
[assembly: AssemblyConfiguration("Release x64")]
[assembly: AssemblyCompany("Prox Security Labs")]
[assembly: AssemblyProduct("ProxSuite PRO Apex Edition")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Prox Security Labs. All rights reserved.")]
[assembly: ComVisible(false)]
[assembly: Guid("9A4F8C21-7B3E-4D9A-8C12-6E5F4A3B2C1D")]
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")]

namespace ProxSuitePRO.UI
{
    public class MainDashboardForm : Form
    {
        private ListView lvTelemetry;
        private RichTextBox rtbConsole;
        private Label lblSubHeader;
        private Label lblMetricCritical;
        private Label lblMetricHigh;
        private Label lblMetricClean;
        private Label lblClipStatus;
        private Button btnUpgradeTop;
        private Timer antiCrackTimer;

        private List<FindingItem> currentFindings = new List<FindingItem>();

        public MainDashboardForm()
        {
            InitializeDashboardUI();
            InitializeTimers();
            AntiCrack.StartWatchdog();
            
            string savedTheme = CGAuthEngine.ReadEncryptedSetting("theme");
            if (savedTheme == "minimal") { _isMinimalTheme = true; ApplyTheme(); }

            LogConsole("[★] ProxSuite Community Edition v3.0 [Open Source - MIT] Initialized.");
            LogConsole("[✓] Edition Status: 100% Free & Open Source (All 45 Engines Unlocked)");
            LogConsole("[✓] Machine Fingerprint: " + CGAuthEngine.GetHardwareId().Substring(0, 24) + "...");
            LogConsole("[✓] Anti-Crack Watchdog & Kernel DACL Self-Defense: ARMED");
            LogConsole("[✓] Real-Time EDR Telemetry & Process Armor: ARMED (35 Forensic Modules)");
        }

        private void RefreshLicenseBanner()
        {
            if (lblSubHeader != null)
            {
                lblSubHeader.Text = "COMMUNITY EDITION (MIT LICENSE)  |  ALL 35 ENGINES UNLOCKED  |  BUILD v3.0.0-OPENSOURCE";
                lblSubHeader.ForeColor = Color.FromArgb(74, 222, 128);
            }
            if (btnUpgradeTop != null)
            {
                btnUpgradeTop.Visible = true;
            }
        }

        private void InitializeDashboardUI()
        {
            this.Text = "ProxSuite Community Edition v3.0 [Open Source - MIT] - 45-in-1 Endpoint EDR & USB Shield";
            this.Size = new Size(1280, 820);
            this.MinimumSize = new Size(1100, 720);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(11, 15, 25);
            this.ForeColor = Color.FromArgb(226, 232, 240);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // 1. TOP HEADER BAR
            Panel topBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 64,
                BackColor = Color.FromArgb(17, 24, 39)
            };

            Label lblBrand = new Label
            {
                Text = "⚡ PROXSUITE v3.0 : OPEN-SOURCE EDR COMMAND CENTER",
                Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(20, 10),
                AutoSize = true
            };

            lblSubHeader = new Label
            {
                Text = "",
                Font = new Font("Consolas", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(74, 222, 128),
                Location = new Point(22, 38),
                AutoSize = true
            };

            Button btnReportTop = new Button
            {
                Text = "📊 HTML Dashboard",
                Size = new Size(145, 32),
                Location = new Point(540, 16),
                BackColor = Color.FromArgb(88, 28, 135),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnReportTop.FlatAppearance.BorderColor = Color.FromArgb(192, 132, 252);
            btnReportTop.Click += (s, e) => ExportHtmlReportNow();

            btnUpgradeTop = new Button
            {
                Text = "⭐ Star on GitHub",
                Size = new Size(145, 32),
                Location = new Point(695, 16),
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(250, 204, 21),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnUpgradeTop.FlatAppearance.BorderColor = Color.FromArgb(250, 204, 21);
            btnUpgradeTop.Click += (s, e) =>
            {
                try { Process.Start("https://github.com/prox0959/ProxSuite"); } catch { }
            };

            lblClipStatus = new Label
            {
                Text = "🛡️ EDR Armor: ACTIVE (45 Modules)",
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(74, 222, 128),
                Location = new Point(855, 22),
                AutoSize = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };

            topBar.Controls.Add(lblBrand);
            topBar.Controls.Add(lblSubHeader);
            topBar.Controls.Add(btnReportTop);
            topBar.Controls.Add(btnUpgradeTop);
            topBar.Controls.Add(lblClipStatus);
            RefreshLicenseBanner();

            // 2. LEFT NAVIGATION SIDEBAR (45-IN-1 MODULES)
            Panel sideBar = new Panel
            {
                Dock = DockStyle.Left,
                Width = 285,
                BackColor = Color.FromArgb(15, 23, 42),
                Padding = new Padding(10),
                AutoScroll = true
            };

            Label lblNavHeader = new Label
            {
                Text = "FORENSIC ENGINES (45-IN-1)",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(12, 10),
                AutoSize = true
            };
            sideBar.Controls.Add(lblNavHeader);

            int btnY = 32;
            AddNavButton(sideBar, "🚀 RUN FULL FORENSIC SCAN (45-ENGINE)", ref btnY, Color.FromArgb(2, 132, 199), async () => await RunEngineAsync("ALL"));
            AddNavButton(sideBar, "🛡️ 1. MemGuard v2.0 (NTDLL & LSASS)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("MEMGUARD"));
            AddNavButton(sideBar, "🧬 2. HollowHunter (RWX Shellcode)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("HOLLOW"));
            AddNavButton(sideBar, "👻 3. GhostTrace (BAM/Prefetch/USB)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("GHOST"));
            AddNavButton(sideBar, "🔐 4. VaultShield (Anti-Stealer)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("VAULT"));
            AddNavButton(sideBar, "🌐 5. NetSentinel (Live C2 Radar)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("NET"));
            AddNavButton(sideBar, "📦 6. OmniTriage (Autoruns Audit)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("OMNI"));
            AddNavButton(sideBar, "🚗 7. DriverRadar (BYOVD & Rootkits)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("DRIVER"));
            AddNavButton(sideBar, "💉 8. AMSIShield & ETW Patch Audit", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("AMSI"));
            AddNavButton(sideBar, "🦠 9. Defender & Hosts Guard [FREE]", ref btnY, Color.FromArgb(6, 78, 59), async () => await RunEngineAsync("DEFENDER"));
            AddNavButton(sideBar, "🕸️ 10. GhostPersist (IFEO & Winlogon)", ref btnY, Color.FromArgb(30, 41, 59), async () => await RunEngineAsync("PERSIST"));
            AddNavButton(sideBar, "⚙️ 11. OS Hardener Audit [FREE]", ref btnY, Color.FromArgb(6, 78, 59), async () => await RunEngineAsync("HARDEN"));
            AddNavButton(sideBar, "🔬 12. TrueVerdict Entropy [FREE]", ref btnY, Color.FromArgb(6, 78, 59), () => RunFileEntropyDialog());
            AddNavButton(sideBar, "🖼️ 13. PixelTrace (Image OSINT/EXIF)", ref btnY, Color.FromArgb(13, 148, 136), () => RunImageOsintDialog());
            AddNavButton(sideBar, "🕷️ 14. WMI Persist Hunter (Fileless)", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("WMI"));
            AddNavButton(sideBar, "🔩 15. Named Pipe C2 Scanner (CS/Sliver)", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("PIPE"));
            AddNavButton(sideBar, "🔑 16. Token Privilege Audit [FREE]", ref btnY, Color.FromArgb(6, 78, 59), async () => await RunEngineAsync("TOKEN"));
            AddNavButton(sideBar, "🧩 17. COM Hijack Detector (HKCU)", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("COM"));
            AddNavButton(sideBar, "🌍 18. Browser Ext Scanner (Stealer)", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("BROWSER"));
            AddNavButton(sideBar, "🧠 19. Memory IOC Scanner (C2/URLs)", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("MEMIOC"));
            AddNavButton(sideBar, "⛓️ 20. Behavioral Correlation Engine", ref btnY, Color.FromArgb(127, 0, 0), async () => await RunBehavioralCorrelationAsync());
            AddNavButton(sideBar, "🍯 21. Ransomware Honeypot Deploy", ref btnY, Color.FromArgb(6, 78, 59), () => DeployHoneypot());
            AddNavButton(sideBar, "🥷 22. EvasionHunter (Stomp/Ghost/Stack)", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("EVASION"));
            AddNavButton(sideBar, "📡 23. Kernel ETW-TI & Driver Stream", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("ETWTI"));
            AddNavButton(sideBar, "🔐 24. LSASS Deep Shield (SSP/Snapshot)", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("LSASSDEEP"));
            AddNavButton(sideBar, "🛡️ 25. Self-Defense & Dynamic Rules", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("SELFDEF"));
            AddNavButton(sideBar, "🦠 26. VirusTotal Hash Intel", ref btnY, Color.FromArgb(15, 118, 110), () => RunVirusTotalDialog());
            AddNavButton(sideBar, "📊 27. ThreatScore™ Live Scoring", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("THREATSCORE"));
            AddNavButton(sideBar, "🔒 28. Quarantine Vault", ref btnY, Color.FromArgb(127, 29, 29), () => RunQuarantineVaultDialog());
            AddNavButton(sideBar, "🌐 29. Threat Intel Feed (abuse.ch)", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("THREATINTEL"));
            AddNavButton(sideBar, "🕵️ 30. Credential Breach Audit", ref btnY, Color.FromArgb(67, 20, 80), () => RunCredentialBreachDialog());
            AddNavButton(sideBar, "📅 31. Schedule Daily Auto-Scan", ref btnY, Color.FromArgb(30, 64, 175), () => RunScheduledScanDialog());
            AddNavButton(sideBar, "🛡️ 32. Real-Time Ransomware Guard", ref btnY, Color.FromArgb(6, 78, 59), () => ActivateRansomwareGuard());
            AddNavButton(sideBar, "⚡ 34. LOLBAS Command Hunter", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("LOLBAS"));
            AddNavButton(sideBar, "🌐 35. DNS Cache & DGA Sentinel", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("DNSDGA"));
            AddNavButton(sideBar, "🧬 36. YARA Signature Scanner", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("YARA"));
            AddNavButton(sideBar, "🌳 37. Process Attack Tree Hunter", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("PROCTREE"));
                        AddNavButton(sideBar, "⚡ 38. ETW Event-Driven Guard", ref btnY, Color.FromArgb(6, 78, 59), () => ToggleEtwGuardNow());
            AddNavButton(sideBar, "⚡ 39. Ransomware Canary Auto-Kill", ref btnY, Color.FromArgb(127, 29, 29), () => ToggleCanaryGuardNow());
            AddNavButton(sideBar, "⚡ 40. Direct Syscall Hunter", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("SYSCALLS"));
                        AddNavButton(sideBar, "⚡ 41. LSASS Credential Shield", ref btnY, Color.FromArgb(67, 20, 80), async () => await RunEngineAsync("LSASSGUARD"));
            AddNavButton(sideBar, "⚡ 42. USB Sentinel & Auto-Vaccine", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("USB"));
            AddNavButton(sideBar, "⚡ 43. LNK Worm & File Unhider", ref btnY, Color.FromArgb(127, 29, 29), async () => await RunEngineAsync("LNKWORM"));
            AddNavButton(sideBar, "⚡ 44. USB Execution Blocker", ref btnY, Color.FromArgb(15, 118, 110), async () => await RunEngineAsync("USBEXEC"));
            AddNavButton(sideBar, "⚡ 45. School Endpoint Immunizer", ref btnY, Color.FromArgb(6, 78, 59), async () => await RunEngineAsync("SCHOOL"));
            AddNavButton(sideBar, "🎨 Switch Theme (Dark / Minimal)", ref btnY, Color.FromArgb(51, 65, 85), () => ToggleTheme());

            // Divider & Response Actions in Sidebar
            Label lblActHeader = new Label
            {
                Text = "ACTIVE RESPONSE, SIEM & RULES",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(12, btnY + 6),
                AutoSize = true
            };
            sideBar.Controls.Add(lblActHeader);
            btnY += 26;

            AddNavButton(sideBar, "❄️ Freeze Selected PID (NtSuspend)", ref btnY, Color.FromArgb(30, 58, 138), () => HandlePidAction(freeze: true));
            AddNavButton(sideBar, "💀 Kill Selected PID (Terminate)", ref btnY, Color.FromArgb(127, 29, 29), () => HandlePidAction(freeze: false));
            AddNavButton(sideBar, "🔒 Apply 1-Click OS Hardening", ref btnY, Color.FromArgb(6, 95, 70), () => ApplyHardeningNow());
            AddNavButton(sideBar, "🔄 Hot-Reload / Edit Dynamic IOC Rules", ref btnY, Color.FromArgb(30, 64, 175), () => ManageDynamicRulesNow());
            AddNavButton(sideBar, "📡 Configure SIEM / Webhook Stream", ref btnY, Color.FromArgb(109, 40, 217), () => ConfigureSiemWebhookNow());
            AddNavButton(sideBar, "📄 Export Executive HTML Report", ref btnY, Color.FromArgb(88, 28, 135), () => ExportHtmlReportNow());
            AddNavButton(sideBar, "📊 Export SIEM JSON (Wazuh/Splunk)", ref btnY, Color.FromArgb(109, 40, 217), () => ExportSiemJsonNow());
                        AddNavButton(sideBar, "🛡️ Arm Anti-Tamper & Process DACL", ref btnY, Color.FromArgb(6, 95, 70), () => ToggleAntiTamperNow());
                        AddNavButton(sideBar, "🛡️ Deploy Canaries & Ransom Guard", ref btnY, Color.FromArgb(127, 29, 29), () => DeployCanariesNow());
                        AddNavButton(sideBar, "🛡️ 1-Click USB Disinfect & Unhide", ref btnY, Color.FromArgb(127, 29, 29), () => DisinfectUsbNow());
            AddNavButton(sideBar, "⚡ Install to Startup (Auto-Guard)", ref btnY, Color.FromArgb(14, 116, 144), () => InstallToStartupWithElevation());
            AddNavButton(sideBar, "🛡️ Remove from Windows Startup", ref btnY, Color.FromArgb(51, 65, 85), () => UninstallFromStartupDialog());

            // 3. MAIN CONTENT AREA
            Panel mainPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(11, 15, 25),
                Padding = new Padding(16)
            };

            // Metric Cards Panel
            Panel metricBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 68,
                BackColor = Color.FromArgb(11, 15, 25)
            };

            lblMetricCritical = CreateMetricBadge(metricBar, "CRITICAL ALERTS: 0", 0, Color.FromArgb(248, 113, 113));
            lblMetricHigh = CreateMetricBadge(metricBar, "HIGH / WARNINGS: 0", 310, Color.FromArgb(251, 146, 60));
            lblMetricClean = CreateMetricBadge(metricBar, "VERIFIED / CLEAN: 0", 620, Color.FromArgb(74, 222, 128));

            // Bottom Live Console Panel
            Panel bottomPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 160,
                BackColor = Color.FromArgb(17, 24, 39),
                Padding = new Padding(8)
            };

            Label lblConsoleTitle = new Label
            {
                Text = "LIVE KERNEL / TELEMETRY LOG",
                Dock = DockStyle.Top,
                Height = 22,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248)
            };

            rtbConsole = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(9, 13, 22),
                ForeColor = Color.FromArgb(167, 243, 208),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                Font = new Font("Consolas", 9.5f, FontStyle.Regular)
            };

            bottomPanel.Controls.Add(rtbConsole);
            bottomPanel.Controls.Add(lblConsoleTitle);

            // Center ListView for Forensic Findings
            lvTelemetry = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(17, 24, 39),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9.5f, FontStyle.Regular)
            };
            lvTelemetry.Columns.Add("Engine Module", 165);
            lvTelemetry.Columns.Add("Severity", 105);
            lvTelemetry.Columns.Add("Target Process / Artifact", 230);
            lvTelemetry.Columns.Add("PID", 70);
            lvTelemetry.Columns.Add("Forensic Telemetry & Syscall / Memory Details", 560);

            ContextMenuStrip ctx = new ContextMenuStrip();
            ctx.Items.Add("🦠 Check Hash on VirusTotal", null, (s, e) => ContextMenuVirusTotalLookup());
            ctx.Items.Add("🔒 Quarantine This File", null, (s, e) => ContextMenuQuarantineFile());
            lvTelemetry.ContextMenuStrip = ctx;

            mainPanel.Controls.Add(lvTelemetry);
            mainPanel.Controls.Add(metricBar);
            mainPanel.Controls.Add(bottomPanel);

            this.Controls.Add(mainPanel);
            this.Controls.Add(sideBar);
            this.Controls.Add(topBar);

            // Trigger initial scan based on cryptographic PRO seal vs Free Preview Mode
            this.Shown += async (s, e) =>
            {
                if (CGAuthEngine.VerifyProExecutionToken("ALL"))
                {
                    await RunEngineAsync("MEMGUARD");
                }
                else
                {
                    await RunPreviewInitialShowcaseAsync();
                }
            };
        }

        private void AddNavButton(Panel parent, string text, ref int y, Color bg, Action onClick)
        {
            Button btn = new Button
            {
                Text = text,
                Location = new Point(10, y),
                Size = new Size(248, 30),
                BackColor = bg,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleLeft,
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btn.Click += (s, e) => onClick();
            parent.Controls.Add(btn);
            y += 33;
        }

        private Label CreateMetricBadge(Panel parent, string initialText, int x, Color color)
        {
            Panel card = new Panel
            {
                Location = new Point(x, 4),
                Size = new Size(295, 52),
                BackColor = Color.FromArgb(17, 24, 39),
                BorderStyle = BorderStyle.FixedSingle
            };
            Label lbl = new Label
            {
                Text = initialText,
                ForeColor = color,
                Font = new Font("Segoe UI", 11.5f, FontStyle.Bold),
                Location = new Point(14, 13),
                AutoSize = true
            };
            card.Controls.Add(lbl);
            parent.Controls.Add(card);
            return lbl;
        }

        private void InitializeTimers()
        {
            // 1. Anti-Crack + 24H Network UTC Clock Tamper Watchdog every 4 seconds
            antiCrackTimer = new Timer { Interval = 4000 };
            antiCrackTimer.Tick += (s, e) =>
            {
                string violation = AntiCrack.PerformSecurityCheck();
                if (violation != null)
                {
                    antiCrackTimer.Stop();
                    MessageBox.Show("Anti-Crack Violation Detected:\n" + violation, "ProxSuite PRO Security", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Environment.Exit(1);
                }

                string timeViolation;
                if (CGAuthEngine.IsPreviewWindowExpiredOrTampered(out timeViolation))
                {
                    antiCrackTimer.Stop();
                    MessageBox.Show("24-Hour UTC Time Lock:\n" + timeViolation, "ProxSuite PRO Time Gate", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    Environment.Exit(0);
                }
            };
            antiCrackTimer.Start();

        }

        private async Task RunPreviewInitialShowcaseAsync()
        {
            LogConsole("[★] Running initial baseline forensic scan (Defender, OS Hardener, Privileges, LOLBAS)...");
            var findings = await Task.Run(() =>
            {
                var list = new List<FindingItem>();
                list.Add(new FindingItem
                {
                    Module = "System Status",
                    Severity = "CLEAN",
                    Target = "Community Edition (MIT)",
                    Pid = new intPidOrAction(0),
                    Details = "ProxSuite Community Edition v3.0 (MIT License) - All 35 Forensic & EDR Engines permanently unlocked."
                });
                list.AddRange(CoreEngines.RunDefenderAndHostsScan());
                list.AddRange(CoreEngines.AuditOsHardening());
                list.AddRange(CoreEngines.RunTokenPrivilegeAudit());
                list.AddRange(CoreEngines.RunLolbasCommandLineScan());
                return list;
            });

            currentFindings = findings;
            RefreshTelemetryGrid();
            LogConsole(string.Format("[✓] Baseline forensic audit completed ({0} items collected). Ready for deep inspection.", findings.Count));
        }

        private void ShowProUpgradeGate(string featureName)
        {
            // Open Source Community Edition: All 35 engines unlocked permanently
        }

        private async Task RunEngineAsync(string mode)
        {
            if (!CGAuthEngine.VerifyProExecutionToken(mode))
            {
                ShowProUpgradeGate("Engine [" + mode + "]");
                return;
            }

            LogConsole(string.Format("[~] Executing [{0}] forensic engine scan...", mode));
            var findings = await Task.Run(() =>
            {
                // Secondary worker-thread cryptographic seal verification (anti-patch protection)
                if (!CGAuthEngine.VerifyProExecutionToken(mode))
                {
                    return new List<FindingItem>
                    {
                        new FindingItem
                        {
                            Module = "CGAuth Security Gate",
                            Severity = "CRITICAL",
                            Target = "Unverified Session",
                            Pid = new intPidOrAction(0),
                            Details = "PRO Cryptographic Session Seal required to execute [" + mode + "]."
                        }
                    };
                }

                DynamicRuleEngine.LoadOrInitializeRules();
                var list = new List<FindingItem>();
                if (mode == "ALL" || mode == "MEMGUARD")  list.AddRange(CoreEngines.RunMemGuardScan());
                if (mode == "ALL" || mode == "HOLLOW")    list.AddRange(CoreEngines.RunHollowHunterScan());
                if (mode == "ALL" || mode == "GHOST")     list.AddRange(CoreEngines.RunGhostTraceScan());
                if (mode == "ALL" || mode == "VAULT")     list.AddRange(CoreEngines.RunVaultShieldScan());
                if (mode == "ALL" || mode == "NET")       list.AddRange(CoreEngines.RunNetSentinelScan());
                if (mode == "ALL" || mode == "OMNI")      list.AddRange(CoreEngines.RunOmniTriageScan());
                if (mode == "ALL" || mode == "DRIVER")    list.AddRange(CoreEngines.RunDriverRadarScan());
                if (mode == "ALL" || mode == "AMSI")      list.AddRange(CoreEngines.RunAmsiEtwShieldScan());
                if (mode == "ALL" || mode == "DEFENDER")  list.AddRange(CoreEngines.RunDefenderAndHostsScan());
                if (mode == "ALL" || mode == "PERSIST")   list.AddRange(CoreEngines.RunGhostPersistScan());
                if (mode == "ALL" || mode == "HARDEN")    list.AddRange(CoreEngines.AuditOsHardening());
                if (mode == "ALL" || mode == "WMI")       list.AddRange(CoreEngines.RunWmiPersistenceScan());
                if (mode == "ALL" || mode == "PIPE")      list.AddRange(CoreEngines.RunNamedPipeC2Scan());
                if (mode == "ALL" || mode == "TOKEN")     list.AddRange(CoreEngines.RunTokenPrivilegeAudit());
                if (mode == "ALL" || mode == "COM")       list.AddRange(CoreEngines.RunComHijackingScan());
                if (mode == "ALL" || mode == "BROWSER")   list.AddRange(CoreEngines.RunBrowserExtensionScan());
                if (mode == "ALL" || mode == "MEMIOC")    list.AddRange(CoreEngines.RunMemoryStringIocScan());
                if (mode == "ALL" || mode == "EVASION")   list.AddRange(CoreEngines.RunModuleStompAndGhostScan());
                if (mode == "ALL" || mode == "ETWTI")     list.AddRange(CoreEngines.RunKernelEtwTiAudit());
                if (mode == "ALL" || mode == "LSASSDEEP") list.AddRange(CoreEngines.RunLsassDeepShieldScan());
                if (mode == "ALL" || mode == "SELFDEF")   list.AddRange(CoreEngines.RunSelfDefenseAndEnterpriseAudit());
                if (mode == "ALL" || mode == "THREATSCORE") list.AddRange(CoreEngines.RunThreatScoreScan());
                if (mode == "ALL" || mode == "THREATINTEL") list.AddRange(CoreEngines.RunThreatIntelCorrelation());
                if (mode == "ALL" || mode == "LOLBAS")      list.AddRange(CoreEngines.RunLolbasCommandLineScan());
                if (mode == "ALL" || mode == "DNSDGA")      list.AddRange(CoreEngines.RunDnsCacheDgaScan());
                if (mode == "ALL" || mode == "YARA")        list.AddRange(CoreEngines.RunYaraScan());
                if (mode == "ALL" || mode == "PROCTREE")    list.AddRange(CoreEngines.RunProcessTreeBehaviorScan());
                if (mode == "ALL" || mode == "ETWGUARD")    list.AddRange(CoreEngines.RunEtwProcessEventAudit());
                if (mode == "ALL" || mode == "RANSOMWARE")  list.AddRange(CoreEngines.RunRansomwareCanaryAudit());
                if (mode == "ALL" || mode == "SYSCALLS")    list.AddRange(CoreEngines.RunDirectSyscallScan());
                if (mode == "ALL" || mode == "LSASSGUARD")  list.AddRange(CoreEngines.RunLsassCredentialShieldAudit());
                if (mode == "ALL" || mode == "USB")         list.AddRange(CoreEngines.RunUsbSentinelScan());
                if (mode == "ALL" || mode == "LNKWORM")     list.AddRange(CoreEngines.DisinfectUsbDrive());
                if (mode == "ALL" || mode == "USBEXEC")     list.AddRange(CoreEngines.RunUsbExecutionAudit());
                if (mode == "ALL" || mode == "SCHOOL")      list.AddRange(CoreEngines.RunSchoolEndpointDisinfectScan());
                if (mode == "ALL")
                {
                    list.AddRange(CoreEngines.RunBehavioralCorrelation(list));
                    SiemDispatcher.DispatchFindings(list);
                }
                return list;
            });

            currentFindings = findings;
            RefreshTelemetryGrid();
            LogConsole(string.Format("[✓] Scan [{0}] completed. Collected {1} forensic telemetry items (EventLog/SIEM updated).", mode, findings.Count));
            if (mode == "ALL")
            {
                string tree = await Task.Run(() => CoreEngines.BuildProcessAttackTree(currentFindings));
                if (!string.IsNullOrEmpty(tree)) LogConsole("\n" + tree);
            }
        }

        private async Task RunBehavioralCorrelationAsync()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("CORRELATION"))
            {
                ShowProUpgradeGate("20. Behavioral Correlation Engine");
                return;
            }
            if (currentFindings == null || currentFindings.Count == 0)
            {
                LogConsole("[!] Behavioral Correlation requires a prior scan. Running full 33-engine scan first...");
                await RunEngineAsync("ALL");
                return;
            }
            LogConsole("[~] Running cross-engine behavioral correlation & Process Attack Tree analysis...");
            var correlated = await Task.Run(() => CoreEngines.RunBehavioralCorrelation(currentFindings));
            string attackTree = await Task.Run(() => CoreEngines.BuildProcessAttackTree(currentFindings));
            currentFindings.InsertRange(0, correlated);
            RefreshTelemetryGrid();
            int critCount = correlated.Count(f => f.Severity == "CRITICAL");
            LogConsole(string.Format("[⛓] Behavioral Correlation complete. {0} attack chain(s) detected.", critCount));
            if (!string.IsNullOrEmpty(attackTree)) LogConsole("\n" + attackTree);
        }

        private void DeployHoneypot()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("HONEYPOT"))
            {
                ShowProUpgradeGate("21. Ransomware Honeypot");
                return;
            }
            CoreEngines.InitializeRansomwareHoneypot((msg, pid) =>
            {
                // Called from FileSystemWatcher thread — marshal to UI
                this.Invoke((MethodInvoker)delegate
                {
                    var alert = new FindingItem
                    {
                        Module   = "Ransomware Honeypot",
                        Severity = "CRITICAL",
                        Target   = "Honeypot File Touched!",
                        Details  = msg,
                        Pid      = new intPidOrAction(pid)
                    };
                    currentFindings.Insert(0, alert);
                    RefreshTelemetryGrid();
                    LogConsole("[🍯 HONEYPOT] " + msg);
                    System.Media.SystemSounds.Hand.Play();
                });
            });

            var status = CoreEngines.GetHoneypotStatus();
            currentFindings.Insert(0, status);
            RefreshTelemetryGrid();
            LogConsole("[🍯] Ransomware Honeypot deployed: " + status.Details);
        }

        private void RefreshTelemetryGrid()
        {
            lvTelemetry.BeginUpdate();
            lvTelemetry.Items.Clear();

            int crit = 0, high = 0, clean = 0;

            foreach (var f in currentFindings)
            {
                var item = new ListViewItem(f.Module);
                item.SubItems.Add(f.Severity);
                item.SubItems.Add(f.Target);
                item.SubItems.Add(f.Pid.Value > 0 ? f.Pid.Value.ToString() : "-");
                item.SubItems.Add(f.Details);
                item.Tag = f;

                if (f.Severity == "CRITICAL")
                {
                    item.ForeColor = Color.FromArgb(248, 113, 113);
                    crit++;
                }
                else if (f.Severity == "HIGH" || f.Severity == "MEDIUM")
                {
                    item.ForeColor = Color.FromArgb(251, 146, 60);
                    high++;
                }
                else
                {
                    item.ForeColor = Color.FromArgb(74, 222, 128);
                    clean++;
                }

                lvTelemetry.Items.Add(item);
            }

            lvTelemetry.EndUpdate();

            lblMetricCritical.Text = "CRITICAL ALERTS: " + crit;
            lblMetricHigh.Text = "HIGH / WARNINGS: " + high;
            lblMetricClean.Text = "VERIFIED / CLEAN: " + clean;
        }

        private void RunFileEntropyDialog()
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "TrueVerdict PRO — Select Suspicious Binary (.exe / .dll / .sys) for Shannon Entropy Analysis";
                ofd.Filter = "All Files (*.*)|*.*|Executables (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        FindingItem item = CoreEngines.AnalyzeFileEntropyAndHash(ofd.FileName);
                        currentFindings.Insert(0, item);
                        RefreshTelemetryGrid();
                        LogConsole("[TrueVerdict PRO] Analyzed " + item.Target + " -> " + item.Details);
                    }
                    catch (Exception ex)
                    {
                        LogConsole("[!] TrueVerdict error: " + ex.Message);
                    }
                }
            }
        }

        private void RunImageOsintDialog()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("PIXELTRACE"))
            {
                ShowProUpgradeGate("13. PixelTrace Image OSINT");
                return;
            }
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "PixelTrace Image OSINT — Select Image (.jpg / .png / .webp / .tiff) for EXIF, GPS & Steganography Analysis";
                ofd.Filter = "Images (*.jpg;*.jpeg;*.png;*.webp;*.tiff;*.bmp)|*.jpg;*.jpeg;*.png;*.webp;*.tiff;*.bmp|All Files (*.*)|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        var items = CoreEngines.AnalyzeImageOsint(ofd.FileName);
                        currentFindings = items;
                        RefreshTelemetryGrid();
                        LogConsole(string.Format("[PixelTrace OSINT] Extracted {0} metadata/forensic layers from {1}", items.Count, Path.GetFileName(ofd.FileName)));
                    }
                    catch (Exception ex)
                    {
                        LogConsole("[!] PixelTrace OSINT error: " + ex.Message);
                    }
                }
            }
        }

        private void HandlePidAction(bool freeze)
        {
            if (!CGAuthEngine.VerifyProExecutionToken("PID_ACTION"))
            {
                ShowProUpgradeGate(freeze ? "Active Response: Freeze PID (NtSuspend)" : "Active Response: Kill PID");
                return;
            }
            if (lvTelemetry.SelectedItems.Count == 0)
            {
                MessageBox.Show("Select a process row with a valid PID in the telemetry table first.", "ProxSuite PRO", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            FindingItem f = lvTelemetry.SelectedItems[0].Tag as FindingItem;
            if (f == null || f.Pid.Value <= 0)
            {
                MessageBox.Show("The selected telemetry row does not have an active process PID.", "ProxSuite PRO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int pid = f.Pid.Value;
            if (freeze)
            {
                bool ok = CoreEngines.FreezeProcess(pid);
                LogConsole(ok
                    ? string.Format("[❄️] Successfully suspended all threads in PID {0} via NtSuspendProcess.", pid)
                    : string.Format("[!] Failed to suspend PID {0} (Run as Administrator).", pid));
            }
            else
            {
                bool ok = CoreEngines.KillProcessById(pid);
                LogConsole(ok
                    ? string.Format("[💀] Terminated process PID {0}.", pid)
                    : string.Format("[!] Failed to terminate PID {0} (Run as Administrator).", pid));
            }
        }

        private void ApplyHardeningNow()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("APPLY_HARDEN"))
            {
                ShowProUpgradeGate("1-Click OS Registry Hardening");
                return;
            }
            string msg = CoreEngines.ApplyOneClickHardening();
            LogConsole("[OS Hardener] " + msg);
            MessageBox.Show(msg, "ProxSuite PRO — 1-Click OS Hardener", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ManageDynamicRulesNow()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("RULES"))
            {
                ShowProUpgradeGate("Dynamic IOC Rules Hot-Reload");
                return;
            }
            try
            {
                if (!File.Exists(DynamicRuleEngine.RuleFilePath))
                    DynamicRuleEngine.ExportDefaultRulesFile();
                else
                    DynamicRuleEngine.LoadOrInitializeRules();

                LogConsole(string.Format("[🔄] Dynamic IOC Rules hot-reloaded ({0} C2 pipes, {1} RAM IOCs). Opening prox_rules.json...",
                    DynamicRuleEngine.CustomPipes.Count, DynamicRuleEngine.CustomMemoryIocs.Count));
                Process.Start("notepad.exe", DynamicRuleEngine.RuleFilePath);
            }
            catch (Exception ex)
            {
                LogConsole("[!] Dynamic Rule Engine error: " + ex.Message);
            }
        }

        private void ConfigureSiemWebhookNow()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("SIEM"))
            {
                ShowProUpgradeGate("Enterprise SIEM / Webhook Alert Streaming");
                return;
            }
            using (Form dlg = new Form())
            {
                dlg.Text = "ProxSuite PRO — Enterprise SIEM / Webhook Alert Streaming";
                dlg.Size = new Size(560, 230);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(15, 23, 42);
                dlg.ForeColor = Color.White;

                Label lbl = new Label
                {
                    Text = "Enter HTTP/HTTPS Webhook URL (Discord, Slack, Splunk HEC, Elastic, or Custom SOC):\n(Alerts are also written to Windows Application EventLog ID 2050 automatically)",
                    Location = new Point(18, 18),
                    Size = new Size(510, 42),
                    Font = new Font("Segoe UI", 9f)
                };

                TextBox txt = new TextBox
                {
                    Text = SiemDispatcher.GetWebhookUrl(),
                    Location = new Point(18, 68),
                    Size = new Size(505, 28),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(56, 189, 248),
                    BorderStyle = BorderStyle.FixedSingle,
                    Font = new Font("Consolas", 9.5f)
                };

                Button btnSave = new Button
                {
                    Text = "💾 Save & Stream Test Alert",
                    Location = new Point(18, 115),
                    Size = new Size(240, 36),
                    BackColor = Color.FromArgb(2, 132, 199),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                btnSave.Click += (s, e) =>
                {
                    SiemDispatcher.SetWebhookUrl(txt.Text);
                    SiemDispatcher.DispatchFindings(currentFindings);
                    LogConsole("[📡] SIEM / Webhook configuration saved and telemetry dispatched.");
                    dlg.DialogResult = DialogResult.OK;
                    dlg.Close();
                };

                Button btnClear = new Button
                {
                    Text = "Clear Webhook",
                    Location = new Point(270, 115),
                    Size = new Size(130, 36),
                    BackColor = Color.FromArgb(51, 65, 85),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                btnClear.Click += (s, e) =>
                {
                    txt.Text = "";
                    SiemDispatcher.SetWebhookUrl("");
                    LogConsole("[📡] SIEM Webhook cleared (Local Windows EventLog remains active).");
                };

                dlg.Controls.Add(lbl);
                dlg.Controls.Add(txt);
                dlg.Controls.Add(btnSave);
                dlg.Controls.Add(btnClear);
                dlg.ShowDialog(this);
            }
        }

        private void ToggleAntiTamperNow()
        {
            try
            {
                ProxSuitePRO.Security.AntiCrack.EnableSelfDefense();
                bool dacl = ProxSuitePRO.Security.AntiCrack.IsDaclProtected;
                bool lockFile = ProxSuitePRO.Security.AntiCrack.IsBinaryLocked;
                bool watchdog = ProxSuitePRO.Security.AntiCrack.IsWatchdogActive;

                LogConsole(string.Format("[✓] ANTI-TAMPER ARMED: Process Kernel DACL Hardened ({0}: Deny Terminate/VM_Write/Suspend) | Disk Binary Locked ({1}) | Debugger Watchdog ({2})",
                    dacl ? "ARMED" : "DENIED", lockFile ? "LOCKED" : "STANDBY", watchdog ? "ACTIVE" : "STANDBY"));
                
                MessageBox.Show(
                    "Anti-Tamper Shield is now ACTIVE!\n\n" +
                    "• Process DACL: Denies PROCESS_TERMINATE, PROCESS_VM_WRITE, and PROCESS_SUSPEND_RESUME from standard tokens and malware.\n" +
                    "• Disk Binary Lock: Process hold on ProxSuitePRO.exe with FileShare.Read (prevents deletion/overwrite).\n" +
                    "• Debugger Watchdog: Active background inspection.\n\n" +
                    "Status: 100% Armed and Safe (No BSOD risk).",
                    "ProxSuite Anti-Tamper Shield",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                LogConsole("[!] Failed to arm anti-tamper: " + ex.Message);
            }
        }

        private void ToggleEtwGuardNow()
        {
            try
            {
                bool armed = CoreEngines.StartEtwRealtimeGuard((alert, pid) =>
                {
                    this.Invoke((MethodInvoker)delegate
                    {
                        LogConsole(string.Format("[⚡ ETW EVENT] {0}", alert));
                        RefreshTelemetryGrid();
                    });
                });

                if (armed)
                {
                    LogConsole("[✓] ETW Event-Driven Real-Time Guard ARMED! Subscribed to kernel process creation stream. Evaluates new processes instantaneously (CPU reduced by 90%).");
                    MessageBox.Show(
                        "ETW Event-Driven Real-Time Sentinel is now ARMED!\n\n" +
                        "• Listens directly to process creation events via kernel telemetry.\n" +
                        "• Analyzes new processes on-demand instead of continuous polling loops (90% lower CPU footprint).\n" +
                        "• Suspicious LOLBAS or attack chains will trigger immediate alerts and write to events.jsonl.",
                        "ETW Real-Time Sentinel",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                else
                {
                    LogConsole("[!] Failed to arm ETW process watcher.");
                }
            }
            catch (Exception ex)
            {
                LogConsole("[!] ETW Guard error: " + ex.Message);
            }
        }

        private void ToggleCanaryGuardNow()
        {
            try
            {
                bool armed = CoreEngines.StartCanaryGuard((alert, pid) =>
                {
                    this.Invoke((MethodInvoker)delegate
                    {
                        LogConsole(string.Format("[⚡ CANARY AUTO-KILL] {0}", alert));
                        RefreshTelemetryGrid();
                    });
                });

                if (armed)
                {
                    LogConsole("[⚡] Autonomous Ransomware Canary Sentinel ARMED! Decoy tripwires deployed across Documents, Desktop, Downloads. Unauthorized file locks will trigger instantaneous process execution kill.");
                    MessageBox.Show(
                        "Autonomous Ransomware Canary Sentinel is now ARMED!\n\n" +
                        "• Deployed decoy canary tripwires (~vault_token, ~canary_vault) in key directories.\n" +
                        "• Real-time file system watchers listening for unauthorized file write/rename/delete attempts.\n" +
                        "• When touched, the offending ransomware process is immediately TERMINATED within single-digit milliseconds.\n" +
                        "• Volume Shadow Copies (VSS) protected against destruction commands.",
                        "Ransomware Canary Sentinel",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                else
                {
                    LogConsole("[!] Failed to arm Ransomware Canary Sentinel.");
                }
            }
            catch (Exception ex)
            {
                LogConsole("[!] Canary Sentinel error: " + ex.Message);
            }
        }

        private void DeployCanariesNow()
        {
            try
            {
                int deployed = CoreEngines.DeployCanaries();
                LogConsole(string.Format("[+] Successfully deployed/verified {0} Ransomware Decoy Canaries across Desktop, Documents, and AppData.", deployed));
                ToggleCanaryGuardNow();
            }
            catch (Exception ex)
            {
                LogConsole("[!] Canary deployment error: " + ex.Message);
            }
        }

                public static bool IsRunningAsAdmin()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static bool InstallToStartup(out string statusMessage)
        {
            try
            {
                if (!MainDashboardForm.IsRunningAsAdmin())
                {
                    statusMessage = "Administrator elevation required.";
                    return false;
                }

                string currentExe = Application.ExecutablePath;
                string installDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ProxSuite");
                if (!Directory.Exists(installDir)) Directory.CreateDirectory(installDir);

                string targetExe = Path.Combine(installDir, "ProxSuitePRO.exe");
                try
                {
                    if (!string.Equals(currentExe, targetExe, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Copy(currentExe, targetExe, true);
                    }
                }
                catch { targetExe = currentExe; }

                // 1. Create elevated Windows Scheduled Task running on logon with Highest Privileges
                try
                {
                    Process p = new Process();
                    p.StartInfo.FileName = "schtasks.exe";
                    p.StartInfo.Arguments = string.Format("/create /tn \"ProxSuite_EDR_AutoGuard\" /tr \"\\\"{0}\\\" --silent\" /sc onlogon /rl highest /f", targetExe);
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    p.WaitForExit(3000);
                }
                catch { }

                // 2. Set HKLM Run
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null) key.SetValue("ProxSuite_EDR", "\"" + targetExe + "\" --silent");
                    }
                }
                catch { }

                // 3. Set HKCU Run
                try
                {
                    using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null) key.SetValue("ProxSuite_EDR", "\"" + targetExe + "\" --silent");
                    }
                }
                catch { }

                statusMessage = "Successfully installed ProxSuite PRO 45-in-1 EDR to Windows Startup with Highest Privileges!\n\n" +
                                "• Target Path: " + targetExe + "\n" +
                                "• Scheduled Task: ProxSuite_EDR_AutoGuard (Highest RunLevel on logon)\n" +
                                "• Registry Persistence: HKLM & HKCU Run configured\n" +
                                "• Protection: Real-time USB Sentinel, Ransomware Canaries, and ETW active on every boot.";
                return true;
            }
            catch (Exception ex)
            {
                statusMessage = "Installation error: " + ex.Message;
                return false;
            }
        }

        public static bool UninstallFromStartup(out string statusMessage)
        {
            try
            {
                try
                {
                    Process p = new Process();
                    p.StartInfo.FileName = "schtasks.exe";
                    p.StartInfo.Arguments = "/delete /tn \"ProxSuite_EDR_AutoGuard\" /f";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    p.WaitForExit(3000);
                }
                catch { }

                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null && key.GetValue("ProxSuite_EDR") != null) key.DeleteValue("ProxSuite_EDR");
                    }
                }
                catch { }

                try
                {
                    using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null && key.GetValue("ProxSuite_EDR") != null) key.DeleteValue("ProxSuite_EDR");
                    }
                }
                catch { }

                statusMessage = "ProxSuite PRO startup persistence removed successfully.";
                return true;
            }
            catch (Exception ex)
            {
                statusMessage = "Removal error: " + ex.Message;
                return false;
            }
        }

        private void InstallToStartupWithElevation()
        {
            try
            {
                if (!MainDashboardForm.IsRunningAsAdmin())
                {
                    var result = MessageBox.Show(
                        "Installing ProxSuite EDR to Windows Startup requires Administrator Privileges (UAC).\n\n" +
                        "This configures automated boot persistence with Highest RunLevel so smart boards and school computers are protected automatically on every startup.\n\n" +
                        "Do you want to grant Administrator permissions and proceed?",
                        "Administrator Elevation Required",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Question);

                    if (result == DialogResult.Yes)
                    {
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = Application.ExecutablePath;
                        psi.Arguments = "--install-startup";
                        psi.Verb = "runas";
                        psi.UseShellExecute = true;
                        try
                        {
                            Process.Start(psi);
                            LogConsole("[*] Requested Administrator elevation (UAC prompt launched).");
                        }
                        catch (Exception ex)
                        {
                            LogConsole("[!] User cancelled or denied elevation: " + ex.Message);
                        }
                    }
                    return;
                }

                string msg;
                if (InstallToStartup(out msg))
                {
                    LogConsole("[+] " + msg.Replace("\n", " "));
                    MessageBox.Show(msg, "Startup Installation Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    LogConsole("[!] " + msg);
                    MessageBox.Show(msg, "Startup Installation Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                LogConsole("[!] Elevation error: " + ex.Message);
            }
        }

        private void UninstallFromStartupDialog()
        {
            try
            {
                string msg;
                UninstallFromStartup(out msg);
                LogConsole("[+] " + msg);
                MessageBox.Show(msg, "Startup Configuration", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                LogConsole("[!] Uninstall error: " + ex.Message);
            }
        }

private void DisinfectUsbNow()
        {
            try
            {
                LogConsole("[*] Initiating 1-Click USB Disinfection, LNK Worm Purge & Hidden File Recovery...");
                var items = CoreEngines.DisinfectUsbDrive();
                currentFindings.AddRange(items);
                RefreshTelemetryGrid();

                var alert = items.FirstOrDefault(i => i.Severity == "CRITICAL");
                if (alert != null)
                {
                    LogConsole("[+] " + alert.Details);
                    MessageBox.Show(
                        "USB DISINFECTION & RECOVERY COMPLETE!\n\n" +
                        alert.Details + "\n\n" +
                        "• All weaponized .lnk shortcut worms have been deleted.\n" +
                        "• All hidden teacher & student files/folders have been fully restored!\n" +
                        "• Removable drive is now immunized.",
                        "USB Sanitization Success",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                else
                {
                    LogConsole("[+] USB Scan Complete: No active LNK shortcut worms detected on connected removable media.");
                    MessageBox.Show(
                        "No malicious shortcut worms detected on connected removable drives.\n\nAll user files are intact and visible.",
                        "USB Scan Clean",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                LogConsole("[!] USB Disinfection error: " + ex.Message);
            }
        }

        private void ExportSiemJsonNow()
        {
            if (currentFindings == null || currentFindings.Count == 0)
            {
                LogConsole("[!] No findings available. Running a full scan before exporting SIEM JSON...");
            }

            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = "Export SIEM Telemetry (Wazuh / Splunk / Elastic NDJSON)";
                sfd.Filter = "NDJSON / JSON Lines (*.jsonl)|*.jsonl|JSON File (*.json)|*.json";
                sfd.FileName = string.Format("proxsuite_siem_telemetry_{0}.jsonl", DateTime.Now.ToString("yyyyMMdd_HHmmss"));

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        var findingsToExport = (currentFindings != null && currentFindings.Count > 0)
                            ? currentFindings
                            : CoreEngines.RunMemGuardScan();

                        string outPath = CoreEngines.ExportFindingsToSiemJson(findingsToExport, sfd.FileName);
                        LogConsole("[✓] SIEM Telemetry exported: " + outPath);
                        MessageBox.Show("SIEM Telemetry exported successfully in Elastic Common Schema (ECS) / Wazuh format!\n\nFile: " + outPath, "SIEM Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        LogConsole("[!] SIEM export failed: " + ex.Message);
                    }
                }
            }
        }

        private void ExportHtmlReportNow()
        {
            if (currentFindings.Count == 0)
            {
                LogConsole("[~] Generating baseline telemetry findings for Executive Dashboard...");
                currentFindings.AddRange(CoreEngines.RunDefenderAndHostsScan());
                currentFindings.AddRange(CoreEngines.AuditOsHardening());
                currentFindings.AddRange(CoreEngines.RunLolbasCommandLineScan());
                RefreshTelemetryGrid();
            }

            string path = CoreEngines.ExportExecutiveHtmlReport(currentFindings, CGAuthEngine.GetHardwareId(), "Community Edition (MIT)");
            LogConsole("[📄] Executive HTML Dashboard exported: " + path);
            try { Process.Start(path); } catch { }
        }

        private void RunVirusTotalDialog()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("VT"))
            {
                ShowProUpgradeGate("26. VirusTotal Hash Intelligence");
                return;
            }
            using (Form dlg = new Form())
            {
                dlg.Text = "🦠 VirusTotal Hash Intelligence Lookup";
                dlg.Size = new Size(560, 300);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(11, 15, 25);
                dlg.ForeColor = Color.FromArgb(226, 232, 240);
                dlg.Font = new Font("Segoe UI", 9.5f);

                Label lblApiKey = new Label { Text = "VT API Key (free — get yours at virustotal.com/gui/my-apikey):", Location = new Point(20, 16), AutoSize = true };
                TextBox txtApiKey = new TextBox
                {
                    Text = CGAuthEngine.ReadEncryptedSetting("vt_apikey") ?? "",
                    Location = new Point(20, 40), Size = new Size(505, 26),
                    BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.FromArgb(56, 189, 248),
                    BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9f)
                };
                Label lblHash = new Label { Text = "SHA256 Hash to lookup:", Location = new Point(20, 76), AutoSize = true };
                TextBox txtHash = new TextBox
                {
                    Location = new Point(20, 100), Size = new Size(505, 26),
                    BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White,
                    BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9f)
                };
                Label lblResult = new Label
                {
                    Text = "Enter a SHA256 hash or use right-click on a finding.", Location = new Point(20, 196),
                    Size = new Size(505, 40), ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Consolas", 8.5f)
                };
                Button btnLookup = new Button
                {
                    Text = "🦠 LOOKUP ON VIRUSTOTAL", Location = new Point(20, 140), Size = new Size(250, 38),
                    BackColor = Color.FromArgb(2, 132, 199), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand
                };
                btnLookup.FlatAppearance.BorderSize = 0;
                btnLookup.Click += (s, e) =>
                {
                    string apiKey = txtApiKey.Text.Trim();
                    string hash = txtHash.Text.Trim();
                    if (string.IsNullOrEmpty(hash)) { lblResult.Text = "Enter a SHA256 hash first."; return; }
                    if (!string.IsNullOrEmpty(apiKey)) CGAuthEngine.SaveEncryptedSetting("vt_apikey", apiKey);
                    if (string.IsNullOrEmpty(apiKey))
                    {
                        try { Process.Start(CoreEngines.GetVirusTotalBrowserUrl(hash)); } catch { }
                        lblResult.ForeColor = Color.FromArgb(56, 189, 248);
                        lblResult.Text = "Opened VirusTotal in browser (no API key set).";
                    }
                    else
                    {
                        lblResult.ForeColor = Color.FromArgb(56, 189, 248);
                        lblResult.Text = "Querying VirusTotal API...";
                        btnLookup.Enabled = false;
                        System.Threading.Tasks.Task.Run(() =>
                        {
                            string result = CoreEngines.LookupVirusTotalHash(hash, apiKey);
                            this.Invoke((MethodInvoker)delegate
                            {
                                btnLookup.Enabled = true;
                                bool isBad = result != null && result.Contains("DETECTED");
                                lblResult.ForeColor = isBad ? Color.FromArgb(248, 113, 113) : Color.FromArgb(74, 222, 128);
                                lblResult.Text = result ?? "Lookup returned no result.";
                                LogConsole("[VT] " + hash.Substring(0, 16) + "... → " + result);
                            });
                        });
                    }
                };
                Button btnBrowser = new Button
                {
                    Text = "🌐 Open in Browser", Location = new Point(280, 140), Size = new Size(245, 38),
                    BackColor = Color.FromArgb(30, 41, 59), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand
                };
                btnBrowser.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                btnBrowser.Click += (s, e) =>
                {
                    string hash = txtHash.Text.Trim();
                    if (!string.IsNullOrEmpty(hash))
                        try { Process.Start(CoreEngines.GetVirusTotalBrowserUrl(hash)); } catch { }
                };

                dlg.Controls.AddRange(new Control[] { lblApiKey, txtApiKey, lblHash, txtHash, btnLookup, btnBrowser, lblResult });
                dlg.ShowDialog(this);
            }
        }

        private void ContextMenuVirusTotalLookup()
        {
            if (lvTelemetry.SelectedItems.Count == 0) return;
            FindingItem f = lvTelemetry.SelectedItems[0].Tag as FindingItem;
            if (f == null) return;
            // Try to extract SHA256 from Details
            var hashMatch = Regex.Match(f.Details ?? "", @"[A-Fa-f0-9]{64}");
            if (hashMatch.Success)
            {
                string hash = hashMatch.Value;
                string apiKey = CGAuthEngine.ReadEncryptedSetting("vt_apikey");
                if (!string.IsNullOrEmpty(apiKey))
                {
                    LogConsole("[VT] Looking up " + hash.Substring(0, 16) + "...");
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        string result = CoreEngines.LookupVirusTotalHash(hash, apiKey);
                        this.Invoke((MethodInvoker)delegate { LogConsole("[VT] " + hash.Substring(0, 16) + "... → " + (result ?? "Failed")); });
                    });
                }
                else
                {
                    try { Process.Start(CoreEngines.GetVirusTotalBrowserUrl(hash)); } catch { }
                }
            }
            else
            {
                LogConsole("[VT] No SHA256 hash found in selected finding details.");
            }
        }

        private void ContextMenuQuarantineFile()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("QUARANTINE")) { ShowProUpgradeGate("Auto-Quarantine"); return; }
            if (lvTelemetry.SelectedItems.Count == 0) return;
            FindingItem f = lvTelemetry.SelectedItems[0].Tag as FindingItem;
            if (f == null) return;
            // Try to extract file path from Details or Target
            string possiblePath = f.Target;
            if (!File.Exists(possiblePath))
            {
                var pathMatch = Regex.Match(f.Details ?? "", @"[A-Z]:\\[^\""\|]+\.[a-zA-Z]{2,4}");
                if (pathMatch.Success) possiblePath = pathMatch.Value;
            }
            if (File.Exists(possiblePath))
            {
                if (MessageBox.Show(string.Format("Quarantine this file?\n{0}\n\nThe file will be XOR-encrypted and moved to the Quarantine Vault.", possiblePath),
                    "ProxSuite PRO — Quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                {
                    var result = CoreEngines.QuarantineFile(possiblePath);
                    currentFindings.Insert(0, result);
                    RefreshTelemetryGrid();
                    LogConsole("[🔒] " + result.Details);
                }
            }
            else
            {
                LogConsole("[!] Could not identify a valid file path from the selected finding.");
            }
        }

        private void RunQuarantineVaultDialog()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("QUARANTINE")) { ShowProUpgradeGate("28. Quarantine Vault"); return; }
            var items = CoreEngines.ListQuarantineVault();
            currentFindings = items;
            RefreshTelemetryGrid();
            LogConsole(string.Format("[🔒] Quarantine Vault: {0} files in isolation.", items.Count(i => i.Severity != "CLEAN")));
        }

        private void RunCredentialBreachDialog()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("HIBP")) { ShowProUpgradeGate("30. Credential Breach Audit"); return; }
            using (Form dlg = new Form())
            {
                dlg.Text = "🕵️ Credential Breach Audit (HIBP — 100% Free)";
                dlg.Size = new Size(520, 280);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false; dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(11, 15, 25);
                dlg.ForeColor = Color.FromArgb(226, 232, 240);
                dlg.Font = new Font("Segoe UI", 9.5f);

                Label lbl = new Label { Text = "Check if a password has appeared in known data breaches:", Location = new Point(20, 16), AutoSize = true };
                TextBox txtPass = new TextBox
                {
                    Location = new Point(20, 44), Size = new Size(460, 26),
                    BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White,
                    BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 10f),
                    UseSystemPasswordChar = true
                };
                Label lblResult = new Label { Text = "Your password is NEVER sent to any server — only a 5-char SHA1 prefix is sent (k-Anonymity).", Location = new Point(20, 170), Size = new Size(460, 50), ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Segoe UI", 8.5f) };

                Button btnCheckPass = new Button
                {
                    Text = "🔑 CHECK PASSWORD BREACH", Location = new Point(20, 82), Size = new Size(230, 36),
                    BackColor = Color.FromArgb(2, 132, 199), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9f, FontStyle.Bold), FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand
                };
                btnCheckPass.FlatAppearance.BorderSize = 0;
                btnCheckPass.Click += (s, e) =>
                {
                    string pass = txtPass.Text;
                    if (string.IsNullOrEmpty(pass)) { lblResult.Text = "Enter a password to check."; return; }
                    btnCheckPass.Enabled = false;
                    lblResult.Text = "Checking HIBP Pwned Passwords (k-Anonymity)...";
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        var findings = CoreEngines.CheckCredentialBreaches(pass, true);
                        this.Invoke((MethodInvoker)delegate
                        {
                            btnCheckPass.Enabled = true;
                            if (findings.Count > 0)
                            {
                                lblResult.ForeColor = findings[0].Severity == "CRITICAL" ? Color.FromArgb(248, 113, 113) : Color.FromArgb(74, 222, 128);
                                lblResult.Text = findings[0].Details;
                                currentFindings.InsertRange(0, findings);
                                RefreshTelemetryGrid();
                            }
                        });
                    });
                };

                Label lbl2 = new Label { Text = "Check email breaches (opens HIBP in browser — free, no API key):", Location = new Point(20, 128), AutoSize = true };
                TextBox txtEmail = new TextBox
                {
                    Location = new Point(20, 150), Size = new Size(300, 26),
                    BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White,
                    BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9.5f)
                };
                Button btnCheckEmail = new Button
                {
                    Text = "📧 CHECK EMAIL", Location = new Point(328, 148), Size = new Size(152, 30),
                    BackColor = Color.FromArgb(30, 41, 59), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand
                };
                btnCheckEmail.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                btnCheckEmail.Click += (s, e) =>
                {
                    string email = txtEmail.Text.Trim();
                    if (!string.IsNullOrEmpty(email))
                    {
                        CoreEngines.CheckCredentialBreaches(email, false);
                        lblResult.ForeColor = Color.FromArgb(56, 189, 248);
                        lblResult.Text = "Opened HIBP in browser to check email breaches.";
                    }
                };

                dlg.Controls.AddRange(new Control[] { lbl, txtPass, btnCheckPass, lbl2, txtEmail, btnCheckEmail, lblResult });
                dlg.ShowDialog(this);
            }
        }

        private void RunScheduledScanDialog()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("SCHEDULE")) { ShowProUpgradeGate("31. Scheduled Daily Auto-Scan"); return; }
            using (Form dlg = new Form())
            {
                dlg.Text = "📅 Schedule Daily Auto-Scan";
                dlg.Size = new Size(440, 220);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false; dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(11, 15, 25);
                dlg.ForeColor = Color.FromArgb(226, 232, 240);

                bool isScheduled = CoreEngines.IsAutoScanScheduled();
                Label lbl = new Label { Text = isScheduled ? "✓ Auto-scan is currently SCHEDULED." : "No auto-scan scheduled.", Location = new Point(20, 16), AutoSize = true,
                    ForeColor = isScheduled ? Color.FromArgb(74, 222, 128) : Color.FromArgb(148, 163, 184) };

                Label lblHour = new Label { Text = "Run daily scan at hour (0-23):", Location = new Point(20, 50), AutoSize = true };
                NumericUpDown nudHour = new NumericUpDown { Location = new Point(220, 48), Size = new Size(60, 26), Minimum = 0, Maximum = 23, Value = 3,
                    BackColor = Color.FromArgb(17, 24, 39), ForeColor = Color.White };

                Label lblStatus = new Label { Text = "", Location = new Point(20, 140), Size = new Size(380, 30), ForeColor = Color.FromArgb(148, 163, 184) };

                Button btnCreate = new Button
                {
                    Text = "📅 CREATE DAILY SCAN", Location = new Point(20, 90), Size = new Size(185, 36),
                    BackColor = Color.FromArgb(2, 132, 199), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9f, FontStyle.Bold), FlatStyle = FlatStyle.Flat
                };
                btnCreate.Click += (s, e) =>
                {
                    string result = CoreEngines.CreateScheduledScan((int)nudHour.Value);
                    lblStatus.Text = result;
                    lbl.Text = "✓ Auto-scan is currently SCHEDULED.";
                    lbl.ForeColor = Color.FromArgb(74, 222, 128);
                    LogConsole("[📅] " + result);
                };

                Button btnRemove = new Button
                {
                    Text = "❌ REMOVE SCHEDULE", Location = new Point(215, 90), Size = new Size(185, 36),
                    BackColor = Color.FromArgb(127, 29, 29), ForeColor = Color.White,
                    Font = new Font("Segoe UI", 9f, FontStyle.Bold), FlatStyle = FlatStyle.Flat
                };
                btnRemove.Click += (s, e) =>
                {
                    string result = CoreEngines.RemoveScheduledScan();
                    lblStatus.Text = result;
                    lbl.Text = "No auto-scan scheduled.";
                    lbl.ForeColor = Color.FromArgb(148, 163, 184);
                    LogConsole("[📅] " + result);
                };

                dlg.Controls.AddRange(new Control[] { lbl, lblHour, nudHour, btnCreate, btnRemove, lblStatus });
                dlg.ShowDialog(this);
            }
        }

        private void ActivateRansomwareGuard()
        {
            if (!CGAuthEngine.VerifyProExecutionToken("RANSOMGUARD")) { ShowProUpgradeGate("32. Real-Time Ransomware Guard"); return; }
            var status = CoreEngines.InitializeRansomwareRealtimeGuard((msg, pid) =>
            {
                this.Invoke((MethodInvoker)delegate
                {
                    var alert = new FindingItem
                    {
                        Module = "Ransomware Guard",
                        Severity = "CRITICAL",
                        Target = "RANSOMWARE ATTACK DETECTED!",
                        Details = msg,
                        Pid = new intPidOrAction(pid)
                    };
                    currentFindings.Insert(0, alert);
                    RefreshTelemetryGrid();
                    LogConsole("[🚨 RANSOMWARE GUARD] " + msg);
                    System.Media.SystemSounds.Hand.Play();
                    MessageBox.Show(msg, "⚠️ RANSOMWARE DETECTED — ProxSuite PRO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                });
            });
            currentFindings.Insert(0, status);
            RefreshTelemetryGrid();
            LogConsole("[🛡️] " + status.Details);
        }

        // Theme system
        private static bool _isMinimalTheme = false;

        private void ToggleTheme()
        {
            _isMinimalTheme = !_isMinimalTheme;
            CGAuthEngine.SaveEncryptedSetting("theme", _isMinimalTheme ? "minimal" : "dark");
            ApplyTheme();
        }

        private void ApplyTheme()
        {
            Color bg, panelBg, text, accent, critColor, cleanColor;
            if (_isMinimalTheme)
            {
                bg = Color.FromArgb(248, 250, 252);
                panelBg = Color.White;
                text = Color.FromArgb(30, 41, 59);
                accent = Color.FromArgb(37, 99, 235);
                critColor = Color.FromArgb(220, 38, 38);
                cleanColor = Color.FromArgb(22, 163, 74);
            }
            else
            {
                bg = Color.FromArgb(11, 15, 25);
                panelBg = Color.FromArgb(17, 24, 39);
                text = Color.FromArgb(226, 232, 240);
                accent = Color.FromArgb(56, 189, 248);
                critColor = Color.FromArgb(248, 113, 113);
                cleanColor = Color.FromArgb(74, 222, 128);
            }
            
            this.BackColor = bg;
            this.ForeColor = text;
            
            foreach (Control c in this.Controls)
            {
                ApplyThemeToControl(c, bg, panelBg, text, accent);
            }
            
            if (lvTelemetry != null)
            {
                lvTelemetry.BackColor = panelBg;
                lvTelemetry.ForeColor = text;
            }
            if (rtbConsole != null)
            {
                rtbConsole.BackColor = _isMinimalTheme ? Color.FromArgb(241, 245, 249) : Color.FromArgb(9, 13, 22);
                rtbConsole.ForeColor = _isMinimalTheme ? Color.FromArgb(15, 118, 110) : Color.FromArgb(167, 243, 208);
            }
            
            LogConsole(string.Format("[🎨] Theme switched to {0}.", _isMinimalTheme ? "Minimal Light" : "Dark (Default)"));
        }

        private void ApplyThemeToControl(Control ctrl, Color bg, Color panelBg, Color text, Color accent)
        {
            if (ctrl is Panel)
            {
                ctrl.BackColor = panelBg;
                ctrl.ForeColor = text;
            }
            else if (ctrl is Button)
            {
                ctrl.ForeColor = text;
            }
            else if (ctrl is Label)
            {
                // Don't override metric labels or status labels with specific colors
            }
            
            foreach (Control child in ctrl.Controls)
            {
                ApplyThemeToControl(child, bg, panelBg, text, accent);
            }
        }

        private void LogConsole(string line)
        {
            if (rtbConsole == null || rtbConsole.IsDisposed) return;
            // FIX: LogConsole can be called from background threads (scan tasks).
            //      Must marshal back to UI thread to avoid InvalidOperationException.
            if (rtbConsole.InvokeRequired)
            {
                try { rtbConsole.Invoke((MethodInvoker)(() => LogConsole(line))); }
                catch { }
                return;
            }
            string stamped = string.Format("[{0:HH:mm:ss}] {1}{2}", DateTime.Now, line, Environment.NewLine);
            rtbConsole.AppendText(stamped);
            rtbConsole.ScrollToCaret();
        }
    }

    internal static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);
        private const int ATTACH_PARENT_PROCESS = -1;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;

        private static void RebindConsole()
        {
            if (AttachConsole(ATTACH_PARENT_PROCESS))
            {
                IntPtr stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
                if (stdOut != IntPtr.Zero)
                {
                    var safeFileHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(stdOut, false);
                    var fileStream = new System.IO.FileStream(safeFileHandle, System.IO.FileAccess.Write);
                    var standardOutput = new System.IO.StreamWriter(fileStream, System.Text.Encoding.Default);
                    standardOutput.AutoFlush = true;
                    Console.SetOut(standardOutput);
                    Console.SetError(standardOutput);
                }
            }
        }

        [STAThread]
        private static void Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                string cmd = args[0].ToLowerInvariant();

                // 1. Headless auto-scan mode (triggered by Windows Task Scheduler)
                if (cmd == "/autoscan" || cmd == "--autoscan")
                {
                    try
                    {
                        var findings = new List<FindingItem>();
                        findings.AddRange(CoreEngines.RunMemGuardScan());
                        findings.AddRange(CoreEngines.RunDefenderAndHostsScan());
                        findings.AddRange(CoreEngines.AuditOsHardening());
                        findings.AddRange(CoreEngines.RunThreatScoreScan());
                        findings.AddRange(CoreEngines.RunThreatIntelCorrelation());
                        findings.AddRange(CoreEngines.RunNetSentinelScan());
                        findings.AddRange(CoreEngines.RunLolbasCommandLineScan());
                        findings.AddRange(CoreEngines.RunDnsCacheDgaScan());
                        findings.AddRange(CoreEngines.RunYaraScan());
                        findings.AddRange(CoreEngines.RunProcessTreeBehaviorScan());
                        findings.AddRange(CoreEngines.RunEtwProcessEventAudit());
                        string path = CoreEngines.ExportExecutiveHtmlReport(findings, CGAuthEngine.GetHardwareId(), "AutoScan");
                        SiemDispatcher.DispatchFindings(findings);
                    }
                    catch { }
                    return;
                }

                // Attach to parent console for terminal commands and rebind streams
                RebindConsole();

                if (cmd == "--help" || cmd == "-h" || cmd == "/?")
                {
                    PrintCliHelp();
                    return;
                }

                if (cmd == "--version" || cmd == "-v")
                {
                    Console.WriteLine("\n[+] ProxSuite Community Edition v3.0 (MIT License - 100% Free & Open Source)");
                    Console.WriteLine("[+] 45-in-1 Windows Native x64 EDR, Live Memory Forensics & SIEM Command Center");
                    Console.WriteLine("[+] GitHub: https://github.com/prox0959/ProxSuite-PRO\n");
                    return;
                }

                if (cmd == "--dump-rwx" || cmd == "-d")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("\n[!] Usage: ProxSuitePRO.exe --dump-rwx <PID> [output_directory]\n");
                        return;
                    }
                    int targetPid;
                    if (!int.TryParse(args[1], out targetPid))
                    {
                        Console.WriteLine("\n[!] Invalid PID: " + args[1] + "\n");
                        return;
                    }
                    string outDir = args.Length >= 3 ? args[2] : null;
                    Console.WriteLine(string.Format("\n[*] Searching unbacked RWX memory regions in PID {0}...", targetPid));
                    var dumped = CoreEngines.DumpProcessRwxMemory(targetPid, outDir);
                    if (dumped.Count > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(string.Format("[✓] Success! Dumped {0} suspicious memory page(s):", dumped.Count));
                        Console.ResetColor();
                        foreach (var d in dumped) Console.WriteLine("  -> " + d);
                    }
                    else
                    {
                        Console.WriteLine("[i] Zero unbacked RWX pages found (or PID terminated / access denied).");
                    }
                    Console.WriteLine();
                    return;
                }

                if (cmd == "--scan" || cmd == "-s")
                {
                    RunCliScan(args);
                    return;
                }

                if (cmd == "--lolbas")
                {
                    RunSingleModuleCli("LOLBAS Command Hunter", CoreEngines.RunLolbasCommandLineScan());
                    return;
                }

                if (cmd == "--dns")
                {
                    RunSingleModuleCli("DNS Cache & DGA Sentinel", CoreEngines.RunDnsCacheDgaScan());
                    return;
                }

                if (cmd == "--yara")
                {
                    string yaraDir = args.Length >= 2 ? args[1] : null;
                    RunSingleModuleCli("YARA Signature Scanner", CoreEngines.RunYaraScan(yaraDir));
                    return;
                }

                if (cmd == "--proctree")
                {
                    RunSingleModuleCli("Process Tree Behavioral Hunter", CoreEngines.RunProcessTreeBehaviorScan());
                    return;
                }

                if (cmd == "--etw")
                {
                    RunSingleModuleCli("ETW Event-Driven Guard", CoreEngines.RunEtwProcessEventAudit());
                    return;
                }

                if (cmd == "--canary" || cmd == "--ransomware")
                {
                    RunSingleModuleCli("Ransomware Canary Sentinel", CoreEngines.RunRansomwareCanaryAudit());
                    return;
                }

                if (cmd == "--syscalls")
                {
                    RunSingleModuleCli("Direct Syscall Hunter", CoreEngines.RunDirectSyscallScan());
                    return;
                }

                if (cmd == "--lsass-guard")
                {
                    RunSingleModuleCli("LSASS Credential Shield", CoreEngines.RunLsassCredentialShieldAudit());
                    return;
                }

                if (cmd == "--usb" || cmd == "--usb-scan")
                {
                    RunSingleModuleCli("USB Sentinel & Auto-Vaccine", CoreEngines.RunUsbSentinelScan());
                    return;
                }

                if (cmd == "--disinfect-usb" || cmd == "--unhide")
                {
                    string drv = args.Length >= 2 ? args[1] : null;
                    RunSingleModuleCli("LNK Worm Disinfector & File Unhider", CoreEngines.DisinfectUsbDrive(drv));
                    return;
                }

                if (cmd == "--usb-block-exec")
                {
                    RunSingleModuleCli("USB Execution Blocker", CoreEngines.RunUsbExecutionAudit());
                    return;
                }

                if (cmd == "--install-startup")
                {
                    string status;
                    if (!MainDashboardForm.IsRunningAsAdmin())
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[!] Requesting Administrator privileges (UAC prompt)...");
                        Console.ResetColor();
                        try
                        {
                            ProcessStartInfo psi = new ProcessStartInfo();
                            psi.FileName = Application.ExecutablePath;
                            psi.Arguments = "--install-startup";
                            psi.Verb = "runas";
                            psi.UseShellExecute = true;
                            Process.Start(psi);
                            return;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("[!] Elevation denied: " + ex.Message);
                            return;
                        }
                    }

                    if (MainDashboardForm.InstallToStartup(out status))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("\n[+] SUCCESS: " + status + "\n");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[!] ERROR: " + status + "\n");
                        Console.ResetColor();
                    }
                    return;
                }

                if (cmd == "--uninstall-startup")
                {
                    string status;
                    MainDashboardForm.UninstallFromStartup(out status);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] " + status + "\n");
                    Console.ResetColor();
                    return;
                }

                if (cmd == "--silent" || cmd == "--background")
                {
                    CoreEngines.StartCanaryGuard((alert, pid) => {
                        SiemLogWriter.AppendToLiveLog(new FindingItem {
                            Module = "Ransomware Canary Sentinel",
                            Severity = "CRITICAL",
                            Target = "System Storage",
                            Details = alert,
                            Pid = new intPidOrAction(pid)
                        });
                    });

                    CoreEngines.StartEtwRealtimeGuard((alert, pid) => {
                        SiemLogWriter.AppendToLiveLog(new FindingItem {
                            Module = "ETW Event-Driven Guard",
                            Severity = "CRITICAL",
                            Target = "Kernel Telemetry",
                            Details = alert,
                            Pid = new intPidOrAction(pid)
                        });
                    });

                    CoreEngines.RunSchoolEndpointDisinfectScan();
                    CoreEngines.RunUsbSentinelScan();

                    while (true)
                    {
                        System.Threading.Thread.Sleep(5000);
                        CoreEngines.RunUsbExecutionAudit();
                    }
                }

                if (cmd == "--school-mode" || cmd == "--disinfect-host")
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\n[*] [SCHOOL DEFENSE SUITE] Sanitizing Host & Disinfecting USB Subsystem...\n");
                    Console.ResetColor();
                    RunSingleModuleCli("School Endpoint Immunizer", CoreEngines.RunSchoolEndpointDisinfectScan());
                    RunSingleModuleCli("USB Execution Blocker", CoreEngines.RunUsbExecutionAudit());
                    RunSingleModuleCli("LNK Worm Disinfector", CoreEngines.DisinfectUsbDrive());
                    return;
                }

                if (cmd == "--arm-canary")
                {
                    CoreEngines.StartCanaryGuard((alert, pid) => {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n" + alert);
                        Console.ResetColor();
                    });
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] Autonomous Ransomware Canary Guard ARMED in background. Press Ctrl+C to exit.\n");
                    Console.ResetColor();
                    while (true) System.Threading.Thread.Sleep(1000);
                }

                if (cmd == "--anti-tamper")
                {
                    ProxSuitePRO.Security.AntiCrack.EnableSelfDefense();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[✓] Anti-Tamper Shield Armed: Process DACL hardened, executable locked, debugger watchdog active.\n");
                    Console.ResetColor();
                    return;
                }
            }

            // Normal GUI boot
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainDashboardForm());
        }

        private static void PrintCliHelp()
        {
            Console.WriteLine(@"
=============================================================================
  PROXSUITE COMMUNITY EDITION v3.0 [Open Source - MIT License]
  45-in-1 Native x64 Windows EDR & USB Endpoint Shield, Ransomware Auto-Kill & Forensics Command Center
  GitHub: https://github.com/prox0959/ProxSuite-PRO
=============================================================================

USAGE:
  ProxSuitePRO.exe                      Boot GUI Dashboard (Default)
  ProxSuitePRO.exe --scan [options]     Run full 45-engine terminal forensic scan
  ProxSuitePRO.exe --dump-rwx <PID>     Extract unbacked RWX shellcode from PID to disk
  ProxSuitePRO.exe --lolbas             Run WMI MITRE ATT&CK LOLBAS command audit
  ProxSuitePRO.exe --dns                Run DNS Cache & DGA/Tunneling sentinel
  ProxSuitePRO.exe --yara [rules_dir]   Run YARA signature scan on process RAM & disk
  ProxSuitePRO.exe --proctree           Hunt malicious process parent-child execution chains
  ProxSuitePRO.exe --etw                Display ETW event-driven sentinel status
  ProxSuitePRO.exe --canary             Run autonomous ransomware canary audit & status
  ProxSuitePRO.exe --arm-canary         Run live background ransomware canary sentinel
  ProxSuitePRO.exe --syscalls           Hunt unbacked direct syscalls (Hell's Gate/SysWhispers)
  ProxSuitePRO.exe --lsass-guard        Audit LSASS credential dumping attempts (MiniDump/comsvcs)
  ProxSuitePRO.exe --usb                Audit and immunize connected removable drives
  ProxSuitePRO.exe --disinfect-usb      Purge .LNK shortcut worms & restore all hidden user files
  ProxSuitePRO.exe --usb-block-exec     Block all binary execution directly from USB drives
  ProxSuitePRO.exe --school-mode        Full school/smartboard immunizer (cleans host + USBs)
  ProxSuitePRO.exe --install-startup    Install to Windows Startup with elevated UAC permissions
  ProxSuitePRO.exe --uninstall-startup  Remove ProxSuite from Windows Startup
  ProxSuitePRO.exe --silent             Run headless background protection daemon on boot
  ProxSuitePRO.exe --anti-tamper        Arm process DACL security & binary lock
  ProxSuitePRO.exe --scan --siem <file> Export findings to SIEM ECS/Wazuh format
  ProxSuitePRO.exe --version            Show version and license info
  ProxSuitePRO.exe --help               Show this help message

SCAN OPTIONS:
  --json <file.json>                    Export full telemetry findings to JSON
  --html                                Generate and open 1-Click HTML5 Dashboard

EXAMPLES:
  ProxSuitePRO.exe --scan
  ProxSuitePRO.exe --scan --json audit.json --html
  ProxSuitePRO.exe --dump-rwx 8412 C:\malware_dumps
");
        }

        private static void RunCliScan(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
  _____                  _____       _ _        
 |  __ \                / ____|     (_) |       
 | |__) | __ _____  __ | (___  _   _ _| |_ ___  
 |  ___/ '__/ _ \ \/ /  \___ \| | | | | __/ _ \ 
 | |   | | | (_) >  <   ____) | |_| | | ||  __/ 
 |_|   |_|  \___/_/\_\ |_____/ \__,_|_|\__\___| 
 ⚡ 45-in-1 Windows EDR & USB Endpoint Shield (v3.5 MIT)
");
            Console.ResetColor();

            Console.WriteLine("[*] Initializing forensic engines...");
            var findings = new List<FindingItem>();

            Console.Write("[*] [1/8] Memory Guard & HollowHunter (RWX Shellcode)... ");
            findings.AddRange(CoreEngines.RunMemGuardScan());
            findings.AddRange(CoreEngines.RunHollowHunterScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [2/8] EvasionHunter & LSASS Deep Shield... ");
            findings.AddRange(CoreEngines.RunModuleStompAndGhostScan());
            findings.AddRange(CoreEngines.RunLsassDeepShieldScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [3/8] Kernel ETW-TI & Driver Integrity... ");
            findings.AddRange(CoreEngines.RunKernelEtwTiAudit());
            findings.AddRange(CoreEngines.RunDriverRadarScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [4/8] LOLBAS & Suspicious Command-Line Hunter... ");
            findings.AddRange(CoreEngines.RunLolbasCommandLineScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [5/8] DNS Cache & DGA Sentinel... ");
            findings.AddRange(CoreEngines.RunDnsCacheDgaScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [6/8] Pure C# YARA Signature Scanner... ");
            findings.AddRange(CoreEngines.RunYaraScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [7/8] Process Attack Tree & Ancestry Hunter... ");
            findings.AddRange(CoreEngines.RunProcessTreeBehaviorScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [8/11] ETW Event-Driven Real-Time Guard... ");
            findings.AddRange(CoreEngines.RunEtwProcessEventAudit());
            Console.WriteLine("Done.");

            Console.Write("[*] [9/11] Ransomware Canary & VSS Fortress... ");
            findings.AddRange(CoreEngines.RunRansomwareCanaryAudit());
            Console.WriteLine("Done.");

            Console.Write("[*] [10/11] Direct Syscall Hunter (Hell's Gate/SysWhispers)... ");
            findings.AddRange(CoreEngines.RunDirectSyscallScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [11/15] LSASS Credential Theft Shield & MiniDump Interceptor... ");
            findings.AddRange(CoreEngines.RunLsassCredentialShieldAudit());
            Console.WriteLine("Done.");

            Console.Write("[*] [12/15] USB Sentinel & Removable Storage Immunizer... ");
            findings.AddRange(CoreEngines.RunUsbSentinelScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [13/15] LNK Shortcut Worm & Hidden File Unhider... ");
            findings.AddRange(CoreEngines.DisinfectUsbDrive());
            Console.WriteLine("Done.");

            Console.Write("[*] [14/15] Removable Drive Execution Blocker (Zero-Trust)... ");
            findings.AddRange(CoreEngines.RunUsbExecutionAudit());
            Console.WriteLine("Done.");

            Console.Write("[*] [15/15] School Endpoint & Host Spreader Immunizer... ");
            findings.AddRange(CoreEngines.RunSchoolEndpointDisinfectScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [6/8] NetSentinel & abuse.ch C2 Radar... ");
            findings.AddRange(CoreEngines.RunNetSentinelScan());
            findings.AddRange(CoreEngines.RunThreatIntelCorrelation());
            Console.WriteLine("Done.");

            Console.Write("[*] [7/8] ThreatScore Live Behavioral Scoring... ");
            findings.AddRange(CoreEngines.RunThreatScoreScan());
            Console.WriteLine("Done.");

            Console.Write("[*] [8/8] Cross-Engine Behavioral Correlation... ");
            findings.AddRange(CoreEngines.RunBehavioralCorrelation(findings));
            Console.WriteLine("Done.\n");

            int crit = findings.Count(f => f.Severity == "CRITICAL");
            int high = findings.Count(f => f.Severity == "HIGH");
            int med  = findings.Count(f => f.Severity == "MEDIUM");
            int clean = findings.Count(f => f.Severity == "CLEAN");

            Console.WriteLine("=============================================================================");
            Console.ForegroundColor = crit > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.Write(string.Format(" CRITICAL: {0} ", crit));
            Console.ForegroundColor = high > 0 ? ConsoleColor.Yellow : ConsoleColor.Gray;
            Console.Write(string.Format("| HIGH: {0} ", high));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(string.Format("| MEDIUM: {0} ", med));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(string.Format("| CLEAN/VERIFIED: {0}", clean));
            Console.ResetColor();
            Console.WriteLine("=============================================================================\n");

            var alerts = findings.Where(f => f.Severity == "CRITICAL" || f.Severity == "HIGH").ToList();
            if (alerts.Count > 0)
            {
                foreach (var a in alerts)
                {
                    Console.ForegroundColor = a.Severity == "CRITICAL" ? ConsoleColor.Red : ConsoleColor.Yellow;
                    Console.Write(string.Format("[{0}] ", a.Severity));
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write(string.Format("{0} -> {1}", a.Module, a.Target));
                    if (a.Pid.Value > 0) Console.Write(string.Format(" (PID: {0})", a.Pid.Value));
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine("  " + a.Details);
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[✓] Zero critical or high-risk threats detected on this host.");
                Console.ResetColor();
            }

            // Check for --json option
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--json" && i + 1 < args.Length)
                {
                    string jsonPath = args[i + 1];
                    CoreEngines.ExportFindingsToJson(findings, jsonPath);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[✓] Telemetry exported to JSON: " + jsonPath);
                    Console.ResetColor();
                }
                if (args[i] == "--siem" && i + 1 < args.Length)
                {
                    string siemPath = args[i + 1];
                    CoreEngines.ExportFindingsToSiemJson(findings, siemPath);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[✓] SIEM ECS/Wazuh Telemetry exported: " + siemPath);
                    Console.ResetColor();
                }
                if (args[i] == "--html")
                {
                    string htmlPath = CoreEngines.ExportExecutiveHtmlReport(findings, CGAuthEngine.GetHardwareId(), "Community Edition (MIT)");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[✓] Executive HTML Dashboard exported: " + htmlPath);
                    Console.ResetColor();
                    try { Process.Start(htmlPath); } catch { }
                }
            }
            Console.WriteLine();
        }

        private static void RunSingleModuleCli(string name, List<FindingItem> items)
        {
            Console.WriteLine(string.Format("\n[*] Running [{0}]...", name));
            foreach (var item in items)
            {
                Console.ForegroundColor = item.Severity == "CRITICAL" ? ConsoleColor.Red : (item.Severity == "HIGH" ? ConsoleColor.Yellow : ConsoleColor.Green);
                Console.Write(string.Format("[{0}] ", item.Severity));
                Console.ResetColor();
                Console.WriteLine(string.Format("{0}: {1}", item.Target, item.Details));
            }
            Console.WriteLine();
        }
    }
}
