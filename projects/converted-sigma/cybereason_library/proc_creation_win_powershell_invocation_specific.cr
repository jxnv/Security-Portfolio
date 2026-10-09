// Title: Suspicious PowerShell Invocations - Specific - ProcessCreation
// ID: 536e2947-3729-478c-9903-745aaffe60d2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-05
// Tags: attack.stealth
// Description: Detects suspicious PowerShell invocation command parameters
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine contains "-nop" AND CommandLine contains " -w " AND CommandLine contains "hidden" AND CommandLine contains " -c " AND CommandLine contains "[Convert]::FromBase64String")) OR ((CommandLine contains " -w " AND CommandLine contains "hidden" AND CommandLine contains "-ep" AND CommandLine contains "bypass" AND CommandLine contains "-Enc")) OR ((CommandLine contains " -w " AND CommandLine contains "hidden" AND CommandLine contains "-noni" AND CommandLine contains "-nop" AND CommandLine contains " -c " AND CommandLine contains "iex" AND CommandLine contains "New-Object")) OR ((CommandLine contains "iex" AND CommandLine contains "New-Object" AND CommandLine contains "Net.WebClient" AND CommandLine contains ".Download")) OR ((CommandLine contains "powershell" AND CommandLine contains "reg" AND CommandLine contains "add" AND CommandLine contains "\\software\\")) OR ((CommandLine contains "bypass" AND CommandLine contains "-noprofile" AND CommandLine contains "-windowstyle" AND CommandLine contains "hidden" AND CommandLine contains "new-object" AND CommandLine contains "system.net.webclient" AND CommandLine contains ".download"))) AND NOT (((CommandLine contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" OR CommandLine contains "Write-ChocolateyWarning"))))
