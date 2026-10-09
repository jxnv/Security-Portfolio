-- Title: Suspicious Modification Of Scheduled Tasks
-- ID: 1c0e41cd-21bb-4433-9acc-4a2cd6367b9b
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-28
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
-- Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
-- Instead they modify the task after creation to include their malicious payload
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\schtasks.exe" AND (CommandLine LIKE '% /Change %' AND CommandLine LIKE '% /TN %')) AND ((CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%cmd /c %' OR CommandLine LIKE '%cmd /k %' OR CommandLine LIKE '%cmd /r %' OR CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd.exe /r %' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%mshta%' OR CommandLine LIKE '%wscript%' OR CommandLine LIKE '%cscript%' OR CommandLine LIKE '%certutil%' OR CommandLine LIKE '%bitsadmin%' OR CommandLine LIKE '%bash.exe%' OR CommandLine LIKE '%bash %' OR CommandLine LIKE '%scrcons%' OR CommandLine LIKE '%wmic %' OR CommandLine LIKE '%wmic.exe%' OR CommandLine LIKE '%forfiles%' OR CommandLine LIKE '%scriptrunner%' OR CommandLine LIKE '%hh.exe%' OR CommandLine LIKE '%hh %')) AND ((CommandLine LIKE '%\\AppData\\Local\\Temp%' OR CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\WINDOWS\\Temp\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Temporary Internet%' OR CommandLine LIKE '%C:\\ProgramData\\%' OR CommandLine LIKE '%C:\\Perflogs\\%' OR CommandLine LIKE '%%ProgramData%%' OR CommandLine LIKE '%%appdata%%' OR CommandLine LIKE '%%comspec%%' OR CommandLine LIKE '%%localappdata%%')))
