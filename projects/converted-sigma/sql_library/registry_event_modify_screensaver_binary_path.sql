-- Title: Path To Screensaver Binary Modified
-- ID: 67a6c006-3fbe-46a7-9074-2ba3b82c3000
-- Status: test
-- Level: medium
-- Author: Bartlomiej Czyz @bczyz1, oscd.community
-- Date: 2020-10-11
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.002
-- Description: Detects value modification of registry key containing path to binary used as screensaver.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Control Panel\\Desktop\\SCRNSAVE.EXE') AND NOT (((Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\explorer.exe'))))
