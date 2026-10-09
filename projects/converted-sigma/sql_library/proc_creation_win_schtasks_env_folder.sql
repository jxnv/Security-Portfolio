-- Title: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
-- ID: 81325ce1-be01-4250-944f-b4789644556f
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-21
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((((CommandLine ILIKE '%:\\Perflogs%' OR CommandLine ILIKE '%:\\Users\\All Users\\%' OR CommandLine ILIKE '%:\\Users\\Default\\%' OR CommandLine ILIKE '%:\\Users\\Public%' OR CommandLine ILIKE '%:\\Windows\\Temp%' OR CommandLine ILIKE '%\\AppData\\Local\\%' OR CommandLine ILIKE '%\\AppData\\Roaming\\%' OR CommandLine ILIKE '%%AppData%%' OR CommandLine ILIKE '%%Public%%')) AND (Image ILIKE '%\\schtasks.exe' AND CommandLine ILIKE '% /create %')) OR ((ParentCommandLine ILIKE '%\\svchost.exe -k netsvcs -p -s Schedule') AND ((CommandLine ILIKE '%:\\Perflogs%' OR CommandLine ILIKE '%:\\Windows\\Temp%' OR CommandLine ILIKE '%\\Users\\Public%' OR CommandLine ILIKE '%%Public%%')))) AND NOT ((((CommandLine ILIKE '%/Create /Xml %' AND CommandLine ILIKE '%\\Temp\\.CR.%' AND CommandLine ILIKE '%\\Avira_Security_Installation.xml%')) OR ((CommandLine ILIKE '%/Create /F /TN%' AND CommandLine ILIKE '%/Xml %' AND CommandLine ILIKE '%\\Temp\\%' AND CommandLine ILIKE '%Avira_%') AND (CommandLine ILIKE '%.tmp\\UpdateFallbackTask.xml%' OR CommandLine ILIKE '%.tmp\\WatchdogServiceControlManagerTimeout.xml%' OR CommandLine ILIKE '%.tmp\\SystrayAutostart.xml%' OR CommandLine ILIKE '%.tmp\\MaintenanceTask.xml%')) OR ((CommandLine ILIKE '%\\Temp\\%' AND CommandLine ILIKE '%/Create /TN \"klcp_update\" /XML %' AND CommandLine ILIKE '%\\klcp_update_task.xml%')) OR ((ParentCommandLine ILIKE '%unattended.ini%') OR (CommandLine ILIKE '%update_task.xml%')) OR (CommandLine ILIKE '%/Create /TN TVInstallRestore /TR%'))))
