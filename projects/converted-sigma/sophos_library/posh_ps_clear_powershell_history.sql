-- Title: Clear PowerShell History - PowerShell
-- ID: 26b692dc-1722-49b2-b496-a8258aa6371d
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date: 2022-01-25
-- Tags: attack.stealth, attack.t1070.003
-- Description: Detects keywords that could indicate clearing PowerShell history
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((ScriptBlockText ILIKE '%Set-PSReadlineOption%' AND ScriptBlockText ILIKE '%–HistorySaveStyle%' AND ScriptBlockText ILIKE '%SaveNothing%')) OR ((ScriptBlockText ILIKE '%Set-PSReadlineOption%' AND ScriptBlockText ILIKE '%-HistorySaveStyle%' AND ScriptBlockText ILIKE '%SaveNothing%'))) OR (((ScriptBlockText ILIKE '%del%' OR ScriptBlockText ILIKE '%Remove-Item%' OR ScriptBlockText ILIKE '%rm%')) AND (ScriptBlockText ILIKE '%(Get-PSReadlineOption).HistorySavePath%')))
