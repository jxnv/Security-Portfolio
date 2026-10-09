// Title: Suspicious Invoke-WebRequest Execution With DirectIP
// ID: 1edff897-9146-48d2-9066-52e8d8f80a2f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-21
// Tags: attack.command-and-control, attack.t1105
// Description: Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*curl *" OR CommandLine: "*Invoke-RestMethod*" OR CommandLine: "*Invoke-WebRequest*" OR CommandLine: "* irm *" OR CommandLine: "*iwr *" OR CommandLine: "*wget *")) AND (((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName: "powershell_ise.EXE" OR OriginalFileName: "PowerShell.EXE" OR OriginalFileName: "pwsh.dll"))) AND ((CommandLine: "*://1*" OR CommandLine: "*://2*" OR CommandLine: "*://3*" OR CommandLine: "*://4*" OR CommandLine: "*://5*" OR CommandLine: "*://6*" OR CommandLine: "*://7*" OR CommandLine: "*://8*" OR CommandLine: "*://9*")))
