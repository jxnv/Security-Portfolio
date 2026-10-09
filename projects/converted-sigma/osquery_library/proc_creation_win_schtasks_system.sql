-- Title: Schtasks Creation Or Modification With SYSTEM Privileges
-- ID: 89ca78fd-b37c-4310-b3d3-81a023f83936
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-28
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\schtasks.exe" AND (CommandLine LIKE '% /change %' OR CommandLine LIKE '% /create %')) AND (CommandLine LIKE '%/ru %') AND ((CommandLine LIKE '%NT AUT%' OR CommandLine LIKE '% SYSTEM %'))) AND NOT ((((CommandLine LIKE '%/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR %' OR CommandLine LIKE '%:\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe%' OR CommandLine LIKE '%/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST%')) OR ((CommandLine LIKE '%Subscription Heartbeat%' AND CommandLine LIKE '%\\HeartbeatConfig.xml%' AND CommandLine LIKE '%\\Microsoft Shared\\OFFICE%')) OR (Image="*\\schtasks.exe" AND (CommandLine LIKE '%/TN TVInstallRestore%' AND CommandLine LIKE '%\\TeamViewer_.exe%')))))
