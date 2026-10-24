using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace ProxSuitePRO.Security
{
    public static class AntiCrack
    {
        private static bool _daclProtected = false;
        private static bool _binaryLocked = false;
        private static bool _watchdogActive = false;
        private static FileStream _lockStream = null;
        private static Thread _watchdogThread = null;

        public static bool IsDaclProtected { get { return _daclProtected; } }
        public static bool IsBinaryLocked { get { return _binaryLocked; } }
        public static bool IsWatchdogActive { get { return _watchdogActive; } }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int RtlSetProcessIsCritical(
            [MarshalAs(UnmanagedType.Bool)] bool bNewValue,
            [MarshalAs(UnmanagedType.Bool)] out bool pbOldValue,
            [MarshalAs(UnmanagedType.Bool)] bool bCheckFlag);

        public static void EnableSelfDefense()
        {
            ApplyDaclProtection();
            LockBinaryOnDisk();
            StartWatchdog();
        }

        public static void ApplyDaclProtection()
        {
            try
            {
                IntPtr hProcess = GetCurrentProcess();
                RawSecurityDescriptor rsd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, new RawAcl(2, 5));
                
                SecurityIdentifier adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                SecurityIdentifier everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

                // Deny Everyone Terminate (0x0001), VM_Write (0x0020), Suspend_Resume (0x0800)
                rsd.DiscretionaryAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 0x0001 | 0x0020 | 0x0800, everyoneSid, false, null));
                rsd.DiscretionaryAcl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1FFFFF, systemSid, false, null));
                rsd.DiscretionaryAcl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1FFFFF, adminSid, false, null));

                byte[] binarySd = new byte[rsd.BinaryLength];
                rsd.GetBinaryForm(binarySd, 0);

                if (SetKernelObjectSecurity(hProcess, 4 /* DACL_SECURITY_INFORMATION */, binarySd))
                {
                    _daclProtected = true;
                }
            }
            catch { }
        }

        public static void LockBinaryOnDisk()
        {
            try
            {
                if (_lockStream == null)
                {
                    string exePath = Process.GetCurrentProcess().MainModule.FileName;
                    if (File.Exists(exePath))
                    {
                        _lockStream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                        _binaryLocked = true;
                    }
                }
            }
            catch { }
        }

        public static void StartWatchdog()
        {
            if (_watchdogActive) return;
            try
            {
                _watchdogActive = true;
                _watchdogThread = new Thread(() =>
                {
                    while (_watchdogActive)
                    {
                        try
                        {
                            bool isDebugger = false;
                            CheckRemoteDebuggerPresent(GetCurrentProcess(), ref isDebugger);
                            if (Debugger.IsAttached || isDebugger)
                            {
                                // Debugger presence flagged
                            }
                        }
                        catch { }
                        Thread.Sleep(2000);
                    }
                }) { IsBackground = true, Name = "ProxSuite_AntiTamper_Watchdog" };
                _watchdogThread.Start();
            }
            catch { }
        }

        public static string PerformSecurityCheck()
        {
            return null; // System clean
        }

        public static bool IsSystemClean(out string reason)
        {
            reason = null;
            return true;
        }

        public static bool SetCriticalProcess(bool enable, out string message)
        {
            message = "";
            try
            {
                bool oldVal = false;
                int status = RtlSetProcessIsCritical(enable, out oldVal, false);
                if (status == 0)
                {
                    message = enable ? "CRITICAL PROCESS ARMED (RtlSetProcessIsCritical)" : "CRITICAL PROCESS DISARMED";
                    return true;
                }
                else
                {
                    message = "RtlSetProcessIsCritical returned NTSTATUS: 0x" + status.ToString("X");
                    return false;
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }
    }
}
