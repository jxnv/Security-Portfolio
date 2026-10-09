-- Title: Clear PowerShell History - PowerShell
-- ID: 26b692dc-1722-49b2-b496-a8258aa6371d
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date: 2022-01-25
-- Tags: attack.stealth, attack.t1070.003
-- Description: Detects keywords that could indicate clearing PowerShell history
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((ScriptBlockText LIKE '%Set-PSReadlineOption%' AND ScriptBlockText LIKE '%–HistorySaveStyle%' AND ScriptBlockText LIKE '%SaveNothing%')) OR ((ScriptBlockText LIKE '%Set-PSReadlineOption%' AND ScriptBlockText LIKE '%-HistorySaveStyle%' AND ScriptBlockText LIKE '%SaveNothing%'))) OR (((ScriptBlockText LIKE '%del%' OR ScriptBlockText LIKE '%Remove-Item%' OR ScriptBlockText LIKE '%rm%')) AND (ScriptBlockText LIKE '%(Get-PSReadlineOption).HistorySavePath%')))
