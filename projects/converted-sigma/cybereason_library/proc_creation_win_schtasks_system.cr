// Title: Schtasks Creation Or Modification With SYSTEM Privileges
// ID: 89ca78fd-b37c-4310-b3d3-81a023f83936
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-28
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\schtasks.exe" AND (CommandLine contains " /change " OR CommandLine contains " /create ")) AND (CommandLine contains "/ru ") AND ((CommandLine contains "NT AUT" OR CommandLine contains " SYSTEM "))) AND NOT ((((CommandLine contains "/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR " OR CommandLine contains ":\\Program Files (x86)\\Avira\\System Speedup\\setup\\avira_speedup_setup.exe" OR CommandLine contains "/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST")) OR ((CommandLine contains "Subscription Heartbeat" AND CommandLine contains "\\HeartbeatConfig.xml" AND CommandLine contains "\\Microsoft Shared\\OFFICE")) OR (Image="*\\schtasks.exe" AND (CommandLine contains "/TN TVInstallRestore" AND CommandLine contains "\\TeamViewer_.exe")))))
