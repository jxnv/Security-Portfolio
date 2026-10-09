-- Title: Suspicious DotNET CLR Usage Log Artifact
-- ID: e0b06658-7d1d-4cd3-bf15-03467507ff7c
-- Status: test
-- Level: high
-- Author: frack113, omkar72, oscd.community, Wojciech Lesicki
-- Date: 2022-11-18
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the creation of Usage Log files by the CLR (clr.dll). These files are named after the executing process once the assembly is finished executing for the first time in the (user) session context.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetFilename ILIKE '%\\UsageLogs\\cmstp.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\cscript.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\mshta.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\msxsl.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\regsvr32.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\rundll32.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\svchost.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\wscript.exe.log' OR TargetFilename ILIKE '%\\UsageLogs\\wmic.exe.log')) AND NOT ((ParentImage ILIKE '%\\MsiExec.exe' AND ParentCommandLine ILIKE '% -Embedding%' AND Image ILIKE '%\\rundll32.exe' AND (CommandLine ILIKE '%Temp%' AND CommandLine ILIKE '%zzzzInvokeManagedCustomActionOutOfProc%'))))
