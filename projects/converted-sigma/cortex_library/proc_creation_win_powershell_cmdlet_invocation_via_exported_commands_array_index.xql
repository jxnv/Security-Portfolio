// Title: PowerShell Dynamic Module Invocation Via ExportedCommands Array Index
// ID: 0c3ebe9f-df09-4e00-be0f-73d4ca8d62f6
// Status: experimental
// Level: high
// Author: Norbert Jaśniewicz (AlphaSOC), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-10-06
// Tags: attack.execution, attack.stealth, attack.t1027.010, attack.t1059.001
// Description: Detects PowerShell processes invoked with obfuscated command lines that enumerate Microsoft.PowerShell.Utility
// exported commands and invoke cmdlets indirectly by array index. This technique is used to evade
// detections that look for explicit strings such as Invoke-RestMethod or Invoke-Expression.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll"))) and (action_process_image_command_line contains "[*]") and ((action_process_image_command_line contains "Get-Module " or action_process_image_command_line contains "gmo ") and (action_process_image_command_line contains "ListAvailable" and action_process_image_command_line contains "Microsoft.PowerShell.Utility" and action_process_image_command_line contains "ExportedCommands" and action_process_image_command_line contains "Values")))
