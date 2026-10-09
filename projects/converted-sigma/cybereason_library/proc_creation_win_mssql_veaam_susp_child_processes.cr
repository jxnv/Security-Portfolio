// Title: Suspicious Child Process Of Veeam Dabatase
// ID: d55b793d-f847-4eea-b59a-5ab09908ac90
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\sqlservr.exe" AND ParentCommandLine contains "VEEAMSQL") AND (((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wsl.exe" OR Image="*\\wt.exe") AND (CommandLine contains "-ex " OR CommandLine contains "bypass" OR CommandLine contains "cscript" OR CommandLine contains "DownloadString" OR CommandLine contains "http://" OR CommandLine contains "https://" OR CommandLine contains "mshta" OR CommandLine contains "regsvr32" OR CommandLine contains "rundll32" OR CommandLine contains "wscript" OR CommandLine contains "copy ")) OR ((Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\netstat.exe" OR Image="*\\nltest.exe" OR Image="*\\ping.exe" OR Image="*\\tasklist.exe" OR Image="*\\whoami.exe"))))
