-- Title: Suspicious Schtasks Execution AppData Folder
-- ID: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-03-15
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
-- Description: Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\schtasks.exe' AND (CommandLine ILIKE '%/Create%' AND CommandLine ILIKE '%/RU%' AND CommandLine ILIKE '%/TR%' AND CommandLine ILIKE '%C:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\%') AND (CommandLine ILIKE '%NT AUT%' OR CommandLine ILIKE '% SYSTEM %')) AND NOT (((ParentImage ILIKE '%\\AppData\\Local\\Temp\\%' AND ParentImage ILIKE '%TeamViewer_.exe%') AND Image ILIKE '%\\schtasks.exe' AND CommandLine ILIKE '%/TN TVInstallRestore%')))
