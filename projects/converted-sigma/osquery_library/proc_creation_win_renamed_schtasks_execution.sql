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

SELECT * FROM processes WHERE (((((CommandLine LIKE '% /tn %' OR CommandLine LIKE '% /tr %' OR CommandLine LIKE '% /sc %' OR CommandLine LIKE '% /st %' OR CommandLine LIKE '% /ru %' OR CommandLine LIKE '% /fo %')) AND ((CommandLine LIKE '% /create %' OR CommandLine LIKE '% /delete %' OR CommandLine LIKE '% /query %' OR CommandLine LIKE '% /change %' OR CommandLine LIKE '% /run %' OR CommandLine LIKE '% /end %'))) AND NOT ((CommandLine LIKE '%schtasks%')) AND NOT (((CommandLine LIKE '%openfiles%' AND CommandLine LIKE '% /query %' AND CommandLine LIKE '% /fo%')))) OR ((OriginalFileName = 'schtasks.exe') AND NOT ((Image="*\\schtasks.exe"))))
