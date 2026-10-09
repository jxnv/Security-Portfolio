// Title: Suspicious PowerShell In Registry Run Keys
// ID: 8d85cf08-bf97-4260-ba49-986a2a65129c
// Status: test
// Level: medium
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-03-17
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects potential PowerShell commands or code within registry run keys
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" OR TargetObject contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" OR TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") AND (Details contains "powershell" OR Details contains "pwsh " OR Details contains "FromBase64String" OR Details contains ".DownloadFile(" OR Details contains ".DownloadString(" OR Details contains " -w hidden " OR Details contains " -w 1 " OR Details contains "-windowstyle hidden" OR Details contains "-window hidden" OR Details contains " -nop " OR Details contains " -encodedcommand " OR Details contains "-ExecutionPolicy Bypass" OR Details contains "Invoke-Expression" OR Details contains "IEX (" OR Details contains "Invoke-Command" OR Details contains "ICM -" OR Details contains "Invoke-WebRequest" OR Details contains "IWR " OR Details contains "Invoke-RestMethod" OR Details contains "IRM " OR Details contains " -noni " OR Details contains " -noninteractive "))
