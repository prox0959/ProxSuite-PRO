using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ProxSuitePRO.Security
{
    /// <summary>
    /// ProxSuite Community Edition - Core Security & Identity Engine (100% Open Source / MIT).
    /// All 35 EDR & Forensics engines unlocked permanently with zero paywalls.
    /// </summary>
    public static class CGAuthEngine
    {
        public static string LicenseStatusMessage = "Open Source Community Edition (MIT License)";
        public static string LicensePlan = "COMMUNITY EDITION (100% FREE & UNLOCKED)";

        private static string _cachedHwid = null;

        public static string GetHardwareId()
        {
            if (!string.IsNullOrEmpty(_cachedHwid)) return _cachedHwid;
            try
            {
                string raw = Environment.MachineName + "_" + Environment.UserName + "_" + Environment.ProcessorCount;
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                    _cachedHwid = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                    return _cachedHwid;
                }
            }
            catch
            {
                return "00000000000000000000000000000000";
            }
        }

        public static bool VerifyProExecutionToken(string mode = null)
        {
            return true; // 100% Unlocked Open Source
        }

        public static bool IsPreviewWindowExpiredOrTampered(out string reason)
        {
            reason = null;
            return false;
        }

        public static void SaveEncryptedSetting(string settingName, string value)
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProxSuite");
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, settingName + ".cfg");
                if (string.IsNullOrEmpty(value))
                {
                    if (File.Exists(path)) File.Delete(path);
                    return;
                }
                byte[] data = Encoding.UTF8.GetBytes(value);
                byte[] enc = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, enc);
            }
            catch { }
        }

        public static string ReadEncryptedSetting(string settingName)
        {
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProxSuite", settingName + ".cfg");
                if (!File.Exists(path)) return null;
                byte[] enc = File.ReadAllBytes(path);
                byte[] data = ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(data);
            }
            catch { return null; }
        }
    }
}
