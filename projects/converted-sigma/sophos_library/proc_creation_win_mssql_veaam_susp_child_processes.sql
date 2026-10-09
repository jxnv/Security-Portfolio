-- Title: Suspicious Child Process Of Veeam Dabatase
-- ID: d55b793d-f847-4eea-b59a-5ab09908ac90
-- Status: test
-- Level: critical
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-04
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\sqlservr.exe' AND ParentCommandLine ILIKE '%VEEAMSQL%') AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wsl.exe' OR Image ILIKE '%\\wt.exe') AND (CommandLine ILIKE '%-ex %' OR CommandLine ILIKE '%bypass%' OR CommandLine ILIKE '%cscript%' OR CommandLine ILIKE '%DownloadString%' OR CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%' OR CommandLine ILIKE '%mshta%' OR CommandLine ILIKE '%regsvr32%' OR CommandLine ILIKE '%rundll32%' OR CommandLine ILIKE '%wscript%' OR CommandLine ILIKE '%copy %')) OR ((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\netstat.exe' OR Image ILIKE '%\\nltest.exe' OR Image ILIKE '%\\ping.exe' OR Image ILIKE '%\\tasklist.exe' OR Image ILIKE '%\\whoami.exe'))))
