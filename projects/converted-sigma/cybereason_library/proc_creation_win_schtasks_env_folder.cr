// Title: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
// ID: 81325ce1-be01-4250-944f-b4789644556f
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-21
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
// Converted by: Sigma Universal SIEM/EDR CLI

(((((CommandLine contains ":\\Perflogs" OR CommandLine contains ":\\Users\\All Users\\" OR CommandLine contains ":\\Users\\Default\\" OR CommandLine contains ":\\Users\\Public" OR CommandLine contains ":\\Windows\\Temp" OR CommandLine contains "\\AppData\\Local\\" OR CommandLine contains "\\AppData\\Roaming\\" OR CommandLine contains "%AppData%" OR CommandLine contains "%Public%")) AND (Image="*\\schtasks.exe" AND CommandLine contains " /create ")) OR ((ParentCommandLine="*\\svchost.exe -k netsvcs -p -s Schedule") AND ((CommandLine contains ":\\Perflogs" OR CommandLine contains ":\\Windows\\Temp" OR CommandLine contains "\\Users\\Public" OR CommandLine contains "%Public%")))) AND NOT ((((CommandLine contains "/Create /Xml " AND CommandLine contains "\\Temp\\.CR." AND CommandLine contains "\\Avira_Security_Installation.xml")) OR ((CommandLine contains "/Create /F /TN" AND CommandLine contains "/Xml " AND CommandLine contains "\\Temp\\" AND CommandLine contains "Avira_") AND (CommandLine contains ".tmp\\UpdateFallbackTask.xml" OR CommandLine contains ".tmp\\WatchdogServiceControlManagerTimeout.xml" OR CommandLine contains ".tmp\\SystrayAutostart.xml" OR CommandLine contains ".tmp\\MaintenanceTask.xml")) OR ((CommandLine contains "\\Temp\\" AND CommandLine contains "/Create /TN \"klcp_update\" /XML " AND CommandLine contains "\\klcp_update_task.xml")) OR ((ParentCommandLine contains "unattended.ini") OR (CommandLine contains "update_task.xml")) OR (CommandLine contains "/Create /TN TVInstallRestore /TR"))))
