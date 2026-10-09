// Title: Suspicious Child Process Of Veeam Dabatase
// ID: d55b793d-f847-4eea-b59a-5ab09908ac90
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\sqlservr.exe" AND ParentCommandLine: "*VEEAMSQL*") AND (((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wsl.exe" OR Image="*\\wt.exe") AND (CommandLine: "*-ex *" OR CommandLine: "*bypass*" OR CommandLine: "*cscript*" OR CommandLine: "*DownloadString*" OR CommandLine: "*http://*" OR CommandLine: "*https://*" OR CommandLine: "*mshta*" OR CommandLine: "*regsvr32*" OR CommandLine: "*rundll32*" OR CommandLine: "*wscript*" OR CommandLine: "*copy *")) OR ((Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\netstat.exe" OR Image="*\\nltest.exe" OR Image="*\\ping.exe" OR Image="*\\tasklist.exe" OR Image="*\\whoami.exe"))))
