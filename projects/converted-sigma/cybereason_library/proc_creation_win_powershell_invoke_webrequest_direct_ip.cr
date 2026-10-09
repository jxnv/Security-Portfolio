// Title: Suspicious Invoke-WebRequest Execution With DirectIP
// ID: 1edff897-9146-48d2-9066-52e8d8f80a2f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-21
// Tags: attack.command-and-control, attack.t1105
// Description: Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "curl " OR CommandLine contains "Invoke-RestMethod" OR CommandLine contains "Invoke-WebRequest" OR CommandLine contains " irm " OR CommandLine contains "iwr " OR CommandLine contains "wget ")) AND (((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "powershell_ise.EXE" OR OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll"))) AND ((CommandLine contains "://1" OR CommandLine contains "://2" OR CommandLine contains "://3" OR CommandLine contains "://4" OR CommandLine contains "://5" OR CommandLine contains "://6" OR CommandLine contains "://7" OR CommandLine contains "://8" OR CommandLine contains "://9")))
