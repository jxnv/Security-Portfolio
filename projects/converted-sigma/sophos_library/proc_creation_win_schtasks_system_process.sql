-- Title: Scheduled Task Creation Masquerading as System Processes
-- ID: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-05
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1053.005, attack.t1036.004, attack.t1036.005
-- Description: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '% /create %' AND (CommandLine ILIKE '% audiodg%' OR CommandLine ILIKE '% conhost%' OR CommandLine ILIKE '% dwm.exe%' OR CommandLine ILIKE '% explorer%' OR CommandLine ILIKE '% lsass%' OR CommandLine ILIKE '% lsm%' OR CommandLine ILIKE '% mmc%' OR CommandLine ILIKE '% msiexec%' OR CommandLine ILIKE '% regsvr32%' OR CommandLine ILIKE '% rundll32%' OR CommandLine ILIKE '% services%' OR CommandLine ILIKE '% spoolsv%' OR CommandLine ILIKE '% svchost%' OR CommandLine ILIKE '% taskeng%' OR CommandLine ILIKE '% taskhost%' OR CommandLine ILIKE '% wininit%' OR CommandLine ILIKE '% winlogon%')) AND ((Image ILIKE '%\\schtasks.exe') OR (OriginalFileName = 'schtasks.exe')))
