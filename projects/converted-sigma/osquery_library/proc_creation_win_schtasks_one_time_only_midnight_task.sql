-- Title: Uncommon One Time Only Scheduled Task At 00:00
-- ID: 970823b7-273b-460a-8afc-3a6811998529
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2022-07-15
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005
-- Description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%wscript%' OR CommandLine LIKE '%vbscript%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%wmic %' OR CommandLine LIKE '%wmic.exe%' OR CommandLine LIKE '%regsvr32.exe%' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%\\AppData\\%')) AND ((Image LIKE '%\\schtasks.exe%') OR (OriginalFileName = 'schtasks.exe')) AND ((CommandLine LIKE '%once%' AND CommandLine LIKE '%00:00%')))
