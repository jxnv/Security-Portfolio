// Title: Suspicious DotNET CLR Usage Log Artifact
// ID: e0b06658-7d1d-4cd3-bf15-03467507ff7c
// Status: test
// Level: high
// Author: frack113, omkar72, oscd.community, Wojciech Lesicki
// Date: 2022-11-18
// Tags: attack.stealth, attack.t1218
// Description: Detects the creation of Usage Log files by the CLR (clr.dll). These files are named after the executing process once the assembly is finished executing for the first time in the (user) session context.
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetFilename="*\\UsageLogs\\cmstp.exe.log" OR TargetFilename="*\\UsageLogs\\cscript.exe.log" OR TargetFilename="*\\UsageLogs\\mshta.exe.log" OR TargetFilename="*\\UsageLogs\\msxsl.exe.log" OR TargetFilename="*\\UsageLogs\\regsvr32.exe.log" OR TargetFilename="*\\UsageLogs\\rundll32.exe.log" OR TargetFilename="*\\UsageLogs\\svchost.exe.log" OR TargetFilename="*\\UsageLogs\\wscript.exe.log" OR TargetFilename="*\\UsageLogs\\wmic.exe.log")) AND NOT ((ParentImage="*\\MsiExec.exe" AND ParentCommandLine: "* -Embedding*" AND Image="*\\rundll32.exe" AND (CommandLine: "*Temp*" AND CommandLine: "*zzzzInvokeManagedCustomActionOutOfProc*"))))
