// Title: Suspicious Schtasks Execution AppData Folder
// ID: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-03-15
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
// Description: Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\schtasks.exe" AND (CommandLine contains "/Create" AND CommandLine contains "/RU" AND CommandLine contains "/TR" AND CommandLine contains "C:\\Users\\" AND CommandLine contains "\\AppData\\Local\\") AND (CommandLine contains "NT AUT" OR CommandLine contains " SYSTEM ")) AND NOT (((ParentImage contains "\\AppData\\Local\\Temp\\" AND ParentImage contains "TeamViewer_.exe") AND Image="*\\schtasks.exe" AND CommandLine contains "/TN TVInstallRestore")))
