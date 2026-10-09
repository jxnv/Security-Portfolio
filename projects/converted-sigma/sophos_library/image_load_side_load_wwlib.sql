-- Title: Potential WWlib.DLL Sideloading
-- ID: e2e01011-5910-4267-9c3b-4149ed5479cf
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-05-18
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "wwlib.dll"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ImageLoaded ILIKE '%\\wwlib.dll') AND NOT (((Image ILIKE 'C:\\Program Files (x86)\\Microsoft Office\\%' OR Image ILIKE 'C:\\Program Files\\Microsoft Office\\%') AND Image ILIKE '%\\winword.exe' AND (ImageLoaded ILIKE 'C:\\Program Files (x86)\\Microsoft Office\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\Microsoft Office\\%'))))
