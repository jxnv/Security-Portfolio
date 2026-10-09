// Title: Potentially Suspicious Child Process Of VsCode
// ID: 5a3164f2-b373-4152-93cf-090b13c12d27
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-26
// Tags: attack.execution, attack.stealth, attack.t1218, attack.t1202
// Description: Detects uncommon or suspicious child processes spawning from a VsCode "code.exe" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\code.exe") AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe") AND (CommandLine contains "Invoke-Expressions" OR CommandLine contains "IEX" OR CommandLine contains "Invoke-Command" OR CommandLine contains "ICM" OR CommandLine contains "DownloadString" OR CommandLine contains "rundll32" OR CommandLine contains "regsvr32" OR CommandLine contains "wscript" OR CommandLine contains "cscript")) OR ((Image="*\\calc.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe")) OR ((Image contains ":\\Users\\Public\\" OR Image contains ":\\Windows\\Temp\\" OR Image contains ":\\Temp\\"))))
