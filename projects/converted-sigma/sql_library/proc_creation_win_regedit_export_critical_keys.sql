-- Title: Exports Critical Registry Keys To a File
-- ID: 82880171-b475-4201-b811-e9c826cd5eaa
-- Status: test
-- Level: high
-- Author: Oddvar Moe, Sander Wiebing, oscd.community
-- Date: 2020-10-12
-- Tags: attack.exfiltration, attack.discovery, attack.t1012
-- Description: Detects the export of a crital Registry key to a file.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% -E %') AND ((CommandLine ILIKE '%hklm%' OR CommandLine ILIKE '%hkey_local_machine%')) AND ((CommandLine ILIKE '%\\system' OR CommandLine ILIKE '%\\sam' OR CommandLine ILIKE '%\\security')) AND ((Image ILIKE '%\\regedit.exe') OR (OriginalFileName = 'REGEDIT.EXE')))
