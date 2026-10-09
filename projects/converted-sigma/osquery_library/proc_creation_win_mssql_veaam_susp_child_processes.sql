-- Title: Suspicious Child Process Of Veeam Dabatase
-- ID: d55b793d-f847-4eea-b59a-5ab09908ac90
-- Status: test
-- Level: critical
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-04
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\sqlservr.exe" AND ParentCommandLine LIKE '%VEEAMSQL%') AND (((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wsl.exe" OR Image="*\\wt.exe") AND (CommandLine LIKE '%-ex %' OR CommandLine LIKE '%bypass%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%DownloadString%' OR CommandLine LIKE '%http://%' OR CommandLine LIKE '%https://%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%wscript%' OR CommandLine LIKE '%copy %')) OR ((Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\netstat.exe" OR Image="*\\nltest.exe" OR Image="*\\ping.exe" OR Image="*\\tasklist.exe" OR Image="*\\whoami.exe"))))
