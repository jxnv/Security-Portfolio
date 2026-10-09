-- Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System
-- ID: 14bcba49-a428-42d9-b943-e2ce0f0f7ae6
-- Status: test
-- Level: high
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-13
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Provider_Name = 'Service Control Manager' AND EventID = 7045 AND (ImagePath ILIKE '%&&set%' AND ImagePath ILIKE '%cmd%' AND ImagePath ILIKE '%/c%' AND ImagePath ILIKE '%-f%') AND (ImagePath ILIKE '%{0}%' OR ImagePath ILIKE '%{1}%' OR ImagePath ILIKE '%{2}%' OR ImagePath ILIKE '%{3}%' OR ImagePath ILIKE '%{4}%' OR ImagePath ILIKE '%{5}%'))
