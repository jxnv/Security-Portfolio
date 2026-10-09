-- Title: Clearing Windows Console History
-- ID: bde47d4b-9987-405c-94c7-b080410e8ea7
-- Status: test
-- Level: high
-- Author: Austin Songer @austinsonger
-- Date: 2021-11-25
-- Tags: attack.stealth, attack.t1070, attack.t1070.003
-- Description: Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%Clear-History%') OR (((ScriptBlockText ILIKE '%Remove-Item%' OR ScriptBlockText ILIKE '%rm%')) AND ((ScriptBlockText ILIKE '%ConsoleHost_history.txt%' OR ScriptBlockText ILIKE '%(Get-PSReadlineOption).HistorySavePath%'))))
