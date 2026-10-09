// Title: Suspicious PowerShell Invocations - Specific - PowerShell Module
// ID: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
// Date: 2017-03-05
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell invocation command parameters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((ContextInfo contains "-nop" and ContextInfo contains " -w " and ContextInfo contains "hidden" and ContextInfo contains " -c " and ContextInfo contains "[Convert]::FromBase64String")) or ((ContextInfo contains " -w " and ContextInfo contains "hidden" and ContextInfo contains "-ep" and ContextInfo contains "bypass" and ContextInfo contains "-Enc")) or ((ContextInfo contains " -w " and ContextInfo contains "hidden" and ContextInfo contains "-noni" and ContextInfo contains "-nop" and ContextInfo contains " -c " and ContextInfo contains "iex" and ContextInfo contains "New-Object")) or ((ContextInfo contains "iex" and ContextInfo contains "New-Object" and ContextInfo contains "Net.WebClient" and ContextInfo contains ".Download")) or ((ContextInfo contains "powershell" and ContextInfo contains "reg" and ContextInfo contains "add") and (ContextInfo contains "\\software\\microsoft\\windows\\currentversion\\run" or ContextInfo contains "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run" or ContextInfo contains "\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run")) or ((ContextInfo contains "bypass" and ContextInfo contains "-noprofile" and ContextInfo contains "-windowstyle" and ContextInfo contains "hidden" and ContextInfo contains "new-object" and ContextInfo contains "system.net.webclient" and ContextInfo contains ".download"))) and not (((ContextInfo contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" or ContextInfo contains "Write-ChocolateyWarning"))))
