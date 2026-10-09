// Title: Clear PowerShell History - PowerShell
// ID: 26b692dc-1722-49b2-b496-a8258aa6371d
// Status: test
// Level: medium
// Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
// Date: 2022-01-25
// Tags: attack.stealth, attack.t1070.003
// Description: Detects keywords that could indicate clearing PowerShell history
// Converted by: Sigma Universal SIEM/EDR CLI

((((ScriptBlockText contains "Set-PSReadlineOption" AND ScriptBlockText contains "–HistorySaveStyle" AND ScriptBlockText contains "SaveNothing")) OR ((ScriptBlockText contains "Set-PSReadlineOption" AND ScriptBlockText contains "-HistorySaveStyle" AND ScriptBlockText contains "SaveNothing"))) OR (((ScriptBlockText contains "del" OR ScriptBlockText contains "Remove-Item" OR ScriptBlockText contains "rm")) AND (ScriptBlockText contains "(Get-PSReadlineOption).HistorySavePath")))
