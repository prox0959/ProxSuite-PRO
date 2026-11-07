@echo off
title ProxSuite Community Edition v3.5 — Standalone Compiler
echo [*] Compiling ProxSuitePRO.exe (x64 Standalone Open-Source Binary)...
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:winexe /platform:x64 /optimize+ /unsafe /nowarn:0219 /out:"%~dp0..\ProxSuitePRO.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll /r:System.Web.Extensions.dll /r:System.Net.Http.dll /r:System.ServiceProcess.dll /r:System.Security.dll /r:Microsoft.CSharp.dll "%~dp0Security\AntiCrack.cs" "%~dp0Security\CGAuthEngine.cs" "%~dp0Engines\CoreEngines.cs" "%~dp0UI\MainDashboardForm.cs"
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS! ProxSuitePRO.exe built with zero external DLL dependencies.
) else (
    echo [!] Build failed.
)
