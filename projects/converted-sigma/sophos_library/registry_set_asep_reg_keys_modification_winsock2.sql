-- Title: WinSock2 Autorun Keys Modification
-- ID: d6c2ce7e-afb5-4337-9ca4-4b5254ed0565
-- Status: test
-- Level: medium
-- Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date: 2019-10-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects modification of autostart extensibility point (ASEP) in registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters%') AND ((TargetObject ILIKE '%\\Protocol_Catalog9\\Catalog_Entries%' OR TargetObject ILIKE '%\\NameSpace_Catalog5\\Catalog_Entries%')) AND NOT (((Details = '(Empty)') OR (Image = 'C:\\Windows\\System32\\MsiExec.exe') OR (Image = 'C:\\Windows\\syswow64\\MsiExec.exe'))))
