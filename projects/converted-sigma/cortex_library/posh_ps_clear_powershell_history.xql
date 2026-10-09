// Title: Clear PowerShell History - PowerShell
// ID: 26b692dc-1722-49b2-b496-a8258aa6371d
// Status: test
// Level: medium
// Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
// Date: 2022-01-25
// Tags: attack.stealth, attack.t1070.003
// Description: Detects keywords that could indicate clearing PowerShell history
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((ScriptBlockText contains "Set-PSReadlineOption" and ScriptBlockText contains "–HistorySaveStyle" and ScriptBlockText contains "SaveNothing")) or ((ScriptBlockText contains "Set-PSReadlineOption" and ScriptBlockText contains "-HistorySaveStyle" and ScriptBlockText contains "SaveNothing"))) or (((ScriptBlockText contains "del" or ScriptBlockText contains "Remove-Item" or ScriptBlockText contains "rm")) and (ScriptBlockText contains "(Get-PSReadlineOption).HistorySavePath")))
