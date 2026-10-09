-- Title: Schtasks Creation Or Modification With SYSTEM Privileges
-- ID: 89ca78fd-b37c-4310-b3d3-81a023f83936
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-28
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\schtasks.exe' AND (CommandLine ILIKE '% /change %' OR CommandLine ILIKE '% /create %')) AND (CommandLine ILIKE '%/ru %') AND ((CommandLine ILIKE '%NT AUT%' OR CommandLine ILIKE '% SYSTEM %'))) AND NOT ((((CommandLine ILIKE '%/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR %' OR CommandLine ILIKE '%:\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe%' OR CommandLine ILIKE '%/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST%')) OR ((CommandLine ILIKE '%Subscription Heartbeat%' AND CommandLine ILIKE '%\\HeartbeatConfig.xml%' AND CommandLine ILIKE '%\\Microsoft Shared\\OFFICE%')) OR (Image ILIKE '%\\schtasks.exe' AND (CommandLine ILIKE '%/TN TVInstallRestore%' AND CommandLine ILIKE '%\\TeamViewer_.exe%')))))
