// Title: Suspicious PowerShell In Registry Run Keys
// ID: 8d85cf08-bf97-4260-ba49-986a2a65129c
// Status: test
// Level: medium
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-03-17
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects potential PowerShell commands or code within registry run keys
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or TargetObject contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") and (Details contains "powershell" or Details contains "pwsh " or Details contains "FromBase64String" or Details contains ".DownloadFile(" or Details contains ".DownloadString(" or Details contains " -w hidden " or Details contains " -w 1 " or Details contains "-windowstyle hidden" or Details contains "-window hidden" or Details contains " -nop " or Details contains " -encodedcommand " or Details contains "-ExecutionPolicy Bypass" or Details contains "Invoke-Expression" or Details contains "IEX (" or Details contains "Invoke-Command" or Details contains "ICM -" or Details contains "Invoke-WebRequest" or Details contains "IWR " or Details contains "Invoke-RestMethod" or Details contains "IRM " or Details contains " -noni " or Details contains " -noninteractive "))
