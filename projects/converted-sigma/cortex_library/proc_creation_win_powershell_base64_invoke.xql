// Title: PowerShell Base64 Encoded Invoke Keyword
// ID: 6385697e-9f1b-40bd-8817-f4a91f40508e
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Harjot Singh, @cyb3rjy0t
// Date: 2022-05-20
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
// Description: Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -e") and ((action_process_image_command_line contains "SQBuAHYAbwBrAGUALQ" or action_process_image_command_line contains "kAbgB2AG8AawBlAC0A" or action_process_image_command_line contains "JAG4AdgBvAGsAZQAtA" or action_process_image_command_line contains "SW52b2tlL" or action_process_image_command_line contains "ludm9rZS" or action_process_image_command_line contains "JbnZva2Ut")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
