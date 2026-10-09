-- Title: Suspicious Schtasks Execution AppData Folder
-- ID: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-03-15
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
-- Description: Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\schtasks.exe" AND (CommandLine LIKE '%/Create%' AND CommandLine LIKE '%/RU%' AND CommandLine LIKE '%/TR%' AND CommandLine LIKE '%C:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\%') AND (CommandLine LIKE '%NT AUT%' OR CommandLine LIKE '% SYSTEM %')) AND NOT (((ParentImage LIKE '%\\AppData\\Local\\Temp\\%' AND ParentImage LIKE '%TeamViewer_.exe%') AND Image="*\\schtasks.exe" AND CommandLine LIKE '%/TN TVInstallRestore%')))
