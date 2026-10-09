-- Title: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
-- ID: 81325ce1-be01-4250-944f-b4789644556f
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-21
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((CommandLine LIKE '%:\\Perflogs%' OR CommandLine LIKE '%:\\Users\\All Users\\%' OR CommandLine LIKE '%:\\Users\\Default\\%' OR CommandLine LIKE '%:\\Users\\Public%' OR CommandLine LIKE '%:\\Windows\\Temp%' OR CommandLine LIKE '%\\AppData\\Local\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%%AppData%%' OR CommandLine LIKE '%%Public%%')) AND (Image="*\\schtasks.exe" AND CommandLine LIKE '% /create %')) OR ((ParentCommandLine="*\\svchost.exe -k netsvcs -p -s Schedule") AND ((CommandLine LIKE '%:\\Perflogs%' OR CommandLine LIKE '%:\\Windows\\Temp%' OR CommandLine LIKE '%\\Users\\Public%' OR CommandLine LIKE '%%Public%%')))) AND NOT ((((CommandLine LIKE '%/Create /Xml %' AND CommandLine LIKE '%\\Temp\\.CR.%' AND CommandLine LIKE '%\\Avira_Security_Installation.xml%')) OR ((CommandLine LIKE '%/Create /F /TN%' AND CommandLine LIKE '%/Xml %' AND CommandLine LIKE '%\\Temp\\%' AND CommandLine LIKE '%Avira_%') AND (CommandLine LIKE '%.tmp\\UpdateFallbackTask.xml%' OR CommandLine LIKE '%.tmp\\WatchdogServiceControlManagerTimeout.xml%' OR CommandLine LIKE '%.tmp\\SystrayAutostart.xml%' OR CommandLine LIKE '%.tmp\\MaintenanceTask.xml%')) OR ((CommandLine LIKE '%\\Temp\\%' AND CommandLine LIKE '%/Create /TN \"klcp_update\" /XML %' AND CommandLine LIKE '%\\klcp_update_task.xml%')) OR ((ParentCommandLine LIKE '%unattended.ini%') OR (CommandLine LIKE '%update_task.xml%')) OR (CommandLine LIKE '%/Create /TN TVInstallRestore /TR%'))))
