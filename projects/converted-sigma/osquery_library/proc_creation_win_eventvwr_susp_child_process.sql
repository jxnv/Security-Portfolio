-- Title: Potentially Suspicious Event Viewer Child Process
-- ID: be344333-921d-4c4d-8bb8-e584cf584780
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-19
-- Tags: attack.privilege-escalation, attack.t1548.002, car.2019-04-001
-- Description: Detects uncommon or suspicious child processes of "eventvwr.exe" which might indicate a UAC bypass attempt
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\eventvwr.exe") AND NOT (((Image="*:\\Windows\\System32\\mmc.exe" OR Image="*:\\Windows\\System32\\WerFault.exe" OR Image="*:\\Windows\\SysWOW64\\WerFault.exe"))))
