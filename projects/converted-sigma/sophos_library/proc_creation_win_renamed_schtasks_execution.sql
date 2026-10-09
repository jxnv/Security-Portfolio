-- Title: Renamed Schtasks Execution
-- ID: f91e51c9-f344-4b32-969b-0b6f6b8537d4
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-11-27
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1036.003, attack.t1053.005
-- Description: Detects the execution of renamed schtasks.exe binary, which is a legitimate Windows utility used for scheduling tasks.
-- One of the very common persistence techniques is schedule malicious tasks using schtasks.exe.
-- Since, it is heavily abused, it is also heavily monitored by security products. To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((((CommandLine ILIKE '% /tn %' OR CommandLine ILIKE '% /tr %' OR CommandLine ILIKE '% /sc %' OR CommandLine ILIKE '% /st %' OR CommandLine ILIKE '% /ru %' OR CommandLine ILIKE '% /fo %')) AND ((CommandLine ILIKE '% /create %' OR CommandLine ILIKE '% /delete %' OR CommandLine ILIKE '% /query %' OR CommandLine ILIKE '% /change %' OR CommandLine ILIKE '% /run %' OR CommandLine ILIKE '% /end %'))) AND NOT ((CommandLine ILIKE '%schtasks%')) AND NOT (((CommandLine ILIKE '%openfiles%' AND CommandLine ILIKE '% /query %' AND CommandLine ILIKE '% /fo%')))) OR ((OriginalFileName = 'schtasks.exe') AND NOT ((Image ILIKE '%\\schtasks.exe'))))
