// Title: PowerShell Execution With Potential Decryption Capabilities
// ID: 434c08ba-8406-4d15-8b24-782cb071a691
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-30
// Tags: attack.execution
// Description: Detects PowerShell commands that decrypt an ".LNK" "file to drop the next stage of the malware.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Get-ChildItem " or action_process_image_command_line contains "dir " or action_process_image_command_line contains "gci " or action_process_image_command_line contains "ls ")) and ((action_process_image_command_line contains "Get-Content " or action_process_image_command_line contains "gc " or action_process_image_command_line contains "cat " or action_process_image_command_line contains "type " or action_process_image_command_line contains "ReadAllBytes")) and (((action_process_image_command_line contains " ^| " and action_process_image_command_line contains "\\*.lnk" and action_process_image_command_line contains "-Recurse" and action_process_image_command_line contains "-Skip ")) or ((action_process_image_command_line contains " -ExpandProperty " and action_process_image_command_line contains "\\*.lnk" and action_process_image_command_line contains "WriteAllBytes" and action_process_image_command_line contains " .length "))) and ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")))
