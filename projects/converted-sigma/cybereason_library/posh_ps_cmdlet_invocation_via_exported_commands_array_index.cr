// Title: PowerShell Dynamic Module Invocation Via ExportedCommands Array Index - PS Script
// ID: 4ff4ad3e-9fb5-4a70-9962-d6ea58090318
// Status: experimental
// Level: medium
// Author: Norbert Jaśniewicz (AlphaSOC)
// Date: 2026-10-06
// Tags: attack.execution, attack.stealth, attack.t1027, attack.t1059.001
// Description: Detects obfuscated PowerShell scripts that enumerate Microsoft.PowerShell.Utility exported commands
// and invoke cmdlets indirectly by array index. This can be used to evade detections
// that look for explicit strings such as Invoke-RestMethod or Invoke-Expression.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "[*]") AND ((ScriptBlockText contains "Get-Module " OR ScriptBlockText contains "gmo ") AND (ScriptBlockText contains "ListAvailable" AND ScriptBlockText contains "Microsoft.PowerShell.Utility" AND ScriptBlockText contains "ExportedCommands" AND ScriptBlockText contains "Values")))
