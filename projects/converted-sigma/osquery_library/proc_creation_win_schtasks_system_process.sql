-- Title: Scheduled Task Creation Masquerading as System Processes
-- ID: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-05
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1053.005, attack.t1036.004, attack.t1036.005
-- Description: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% /create %' AND (CommandLine LIKE '% audiodg%' OR CommandLine LIKE '% conhost%' OR CommandLine LIKE '% dwm.exe%' OR CommandLine LIKE '% explorer%' OR CommandLine LIKE '% lsass%' OR CommandLine LIKE '% lsm%' OR CommandLine LIKE '% mmc%' OR CommandLine LIKE '% msiexec%' OR CommandLine LIKE '% regsvr32%' OR CommandLine LIKE '% rundll32%' OR CommandLine LIKE '% services%' OR CommandLine LIKE '% spoolsv%' OR CommandLine LIKE '% svchost%' OR CommandLine LIKE '% taskeng%' OR CommandLine LIKE '% taskhost%' OR CommandLine LIKE '% wininit%' OR CommandLine LIKE '% winlogon%')) AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')))
