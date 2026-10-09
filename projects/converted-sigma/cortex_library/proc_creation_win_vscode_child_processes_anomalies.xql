// Title: Potentially Suspicious Child Process Of VsCode
// ID: 5a3164f2-b373-4152-93cf-090b13c12d27
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-26
// Tags: attack.execution, attack.stealth, attack.t1218, attack.t1202
// Description: Detects uncommon or suspicious child processes spawning from a VsCode "code.exe" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\code.exe") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cmd.exe") and (action_process_image_command_line contains "Invoke-Expressions" or action_process_image_command_line contains "IEX" or action_process_image_command_line contains "Invoke-Command" or action_process_image_command_line contains "ICM" or action_process_image_command_line contains "DownloadString" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "cscript")) or ((action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains ":\\Windows\\Temp\\" or action_process_image_path contains ":\\Temp\\"))))
