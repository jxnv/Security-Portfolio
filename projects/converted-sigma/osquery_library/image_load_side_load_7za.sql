-- Title: Potential 7za.DLL Sideloading
-- ID: 4f6edb78-5c21-42ab-a558-fd2a6fc1fd57
-- Status: test
-- Level: low
-- Author: X__Junior
-- Date: 2023-06-09
-- Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "7za.dll"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ImageLoaded="*\\7za.dll") AND NOT (((Image="C:\\Program Files (x86)\\*" OR Image="C:\\Program Files\\*") AND (ImageLoaded="C:\\Program Files (x86)\\*" OR ImageLoaded="C:\\Program Files\\*"))))
