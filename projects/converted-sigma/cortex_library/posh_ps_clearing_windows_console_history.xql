// Title: Clearing Windows Console History
// ID: bde47d4b-9987-405c-94c7-b080410e8ea7
// Status: test
// Level: high
// Author: Austin Songer @austinsonger
// Date: 2021-11-25
// Tags: attack.stealth, attack.t1070, attack.t1070.003
// Description: Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Clear-History") or (((ScriptBlockText contains "Remove-Item" or ScriptBlockText contains "rm")) and ((ScriptBlockText contains "ConsoleHost_history.txt" or ScriptBlockText contains "(Get-PSReadlineOption).HistorySavePath"))))
