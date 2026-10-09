-- Title: Suspicious Command Patterns In Scheduled Task Creation
-- ID: f2c64357-b1d2-41b7-849f-34d2682c0fad
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-23
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects scheduled task creation using "schtasks" that contain potentially suspicious or uncommon commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\schtasks.exe" AND CommandLine LIKE '%/Create %') AND ((((CommandLine LIKE '%/sc minute %' OR CommandLine LIKE '%/ru system %')) AND ((CommandLine LIKE '%cmd /c%' OR CommandLine LIKE '%cmd /k%' OR CommandLine LIKE '%cmd /r%' OR CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd.exe /r %'))) OR ((CommandLine LIKE '% -decode %' OR CommandLine LIKE '% -enc %' OR CommandLine LIKE '% -w hidden %' OR CommandLine LIKE '% bypass %' OR CommandLine LIKE '% IEX%' OR CommandLine LIKE '%.DownloadData%' OR CommandLine LIKE '%.DownloadFile%' OR CommandLine LIKE '%.DownloadString%' OR CommandLine LIKE '%/c start /min %' OR CommandLine LIKE '%FromBase64String%' OR CommandLine LIKE '%mshta http%' OR CommandLine LIKE '%mshta.exe http%')) OR (((CommandLine LIKE '%:\\ProgramData\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Tmp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\%' OR CommandLine LIKE '%%AppData%%' OR CommandLine LIKE '%%Temp%%' OR CommandLine LIKE '%%tmp%%')) AND ((CommandLine LIKE '%cscript%' OR CommandLine LIKE '%curl%' OR CommandLine LIKE '%wscript%')))))
