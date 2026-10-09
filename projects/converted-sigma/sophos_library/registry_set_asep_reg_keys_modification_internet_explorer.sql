-- Title: Internet Explorer Autorun Keys Modification
-- ID: a80f662f-022f-4429-9b8c-b1a41aaa6688
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects modification of autostart extensibility point (ASEP) in registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\Software\\Wow6432Node\\Microsoft\\Internet Explorer%' OR TargetObject ILIKE '%\\Software\\Microsoft\\Internet Explorer%')) AND ((TargetObject ILIKE '%\\Toolbar%' OR TargetObject ILIKE '%\\Extensions%' OR TargetObject ILIKE '%\\Explorer Bars%')) AND NOT (((Details = '(Empty)') OR ((TargetObject ILIKE '%\\Extensions\\{2670000A-7350-4f3c-8081-5663EE0C6C49}%' OR TargetObject ILIKE '%\\Extensions\\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}%' OR TargetObject ILIKE '%\\Extensions\\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}%' OR TargetObject ILIKE '%\\Extensions\\{A95fe080-8f5d-11d2-a20b-00aa003c157a}%')) OR ((TargetObject ILIKE '%\\Toolbar\\ShellBrowser\\ITBar7Layout' OR TargetObject ILIKE '%\\Toolbar\\ShowDiscussionButton' OR TargetObject ILIKE '%\\Toolbar\\Locked')))))
