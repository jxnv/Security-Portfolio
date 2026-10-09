// Title: Potential PowerShell Execution Via DLL
// ID: 6812a10b-60ea-420c-832f-dfcc33b646ba
// Status: test
// Level: high
// Author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
// Date: 2018-08-25
// Tags: attack.stealth, attack.t1218.011
// Description: Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll.
// This detection assumes that PowerShell commands are passed via the CommandLine.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "Default.GetString" OR CommandLine contains "DownloadString" OR CommandLine contains "FromBase64String" OR CommandLine contains "ICM " OR CommandLine contains "IEX " OR CommandLine contains "Invoke-Command" OR CommandLine contains "Invoke-Expression")) AND (((Image="*\\InstallUtil.exe" OR Image="*\\RegAsm.exe" OR Image="*\\RegSvcs.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe")) OR ((OriginalFileName == "InstallUtil.exe" OR OriginalFileName == "RegAsm.exe" OR OriginalFileName == "RegSvcs.exe" OR OriginalFileName == "REGSVR32.EXE" OR OriginalFileName == "RUNDLL32.EXE"))))
