-- Title: Potential AVKkid.DLL Sideloading
-- ID: 952ed57c-8f99-453d-aee0-53a49c22f95d
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-08-03
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "AVKkid.dll"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\AVKkid.dll') AND NOT (((Image ILIKE '%C:\\Program Files (x86)\\G DATA\\%' OR Image ILIKE '%C:\\Program Files\\G DATA\\%') AND Image ILIKE '%\\AVKKid.exe' AND (ImageLoaded ILIKE 'C:\\Program Files (x86)\\G DATA\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\G DATA\\%'))))
