// Title: Suspicious PowerShell Invocations - Specific - PowerShell Module
// ID: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
// Date: 2017-03-05
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell invocation command parameters
// Converted by: Sigma Universal SIEM/EDR CLI

((((ContextInfo contains "-nop" AND ContextInfo contains " -w " AND ContextInfo contains "hidden" AND ContextInfo contains " -c " AND ContextInfo contains "[Convert]::FromBase64String")) OR ((ContextInfo contains " -w " AND ContextInfo contains "hidden" AND ContextInfo contains "-ep" AND ContextInfo contains "bypass" AND ContextInfo contains "-Enc")) OR ((ContextInfo contains " -w " AND ContextInfo contains "hidden" AND ContextInfo contains "-noni" AND ContextInfo contains "-nop" AND ContextInfo contains " -c " AND ContextInfo contains "iex" AND ContextInfo contains "New-Object")) OR ((ContextInfo contains "iex" AND ContextInfo contains "New-Object" AND ContextInfo contains "Net.WebClient" AND ContextInfo contains ".Download")) OR ((ContextInfo contains "powershell" AND ContextInfo contains "reg" AND ContextInfo contains "add") AND (ContextInfo contains "\\software\\microsoft\\windows\\currentversion\\run" OR ContextInfo contains "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run" OR ContextInfo contains "\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run")) OR ((ContextInfo contains "bypass" AND ContextInfo contains "-noprofile" AND ContextInfo contains "-windowstyle" AND ContextInfo contains "hidden" AND ContextInfo contains "new-object" AND ContextInfo contains "system.net.webclient" AND ContextInfo contains ".download"))) AND NOT (((ContextInfo contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" OR ContextInfo contains "Write-ChocolateyWarning"))))
