// Title: Suspicious MsiExec Embedding Parent
// ID: 4a2a2c3e-209f-4d01-b513-4155a540b469
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-04-16
// Tags: attack.stealth, attack.t1218.007
// Description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe") AND (ParentCommandLine contains "MsiExec.exe" AND ParentCommandLine contains "-Embedding ")) AND NOT (((Image="*:\\Windows\\System32\\cmd.exe" AND CommandLine contains "C:\\Program Files\\SplunkUniversalForwarder\\bin\\") OR ((CommandLine contains "\\DismFoDInstall.cmd") OR ((ParentCommandLine contains "\\MsiExec.exe -Embedding " AND ParentCommandLine contains "Global\\MSI0000"))))))
