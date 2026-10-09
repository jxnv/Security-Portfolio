// Title: PowerShell Base64 Encoded Invoke Keyword
// ID: 6385697e-9f1b-40bd-8817-f4a91f40508e
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Harjot Singh, @cyb3rjy0t
// Date: 2022-05-20
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
// Description: Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "* -e*") AND ((CommandLine: "*SQBuAHYAbwBrAGUALQ*" OR CommandLine: "*kAbgB2AG8AawBlAC0A*" OR CommandLine: "*JAG4AdgBvAGsAZQAtA*" OR CommandLine: "*SW52b2tlL*" OR CommandLine: "*ludm9rZS*" OR CommandLine: "*JbnZva2Ut*")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName: "PowerShell.EXE" OR OriginalFileName: "pwsh.dll"))))
