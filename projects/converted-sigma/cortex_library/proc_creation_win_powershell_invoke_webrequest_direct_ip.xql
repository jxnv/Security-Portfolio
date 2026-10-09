// Title: Suspicious Invoke-WebRequest Execution With DirectIP
// ID: 1edff897-9146-48d2-9066-52e8d8f80a2f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-21
// Tags: attack.command-and-control, attack.t1105
// Description: Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "curl " or action_process_image_command_line contains "Invoke-RestMethod" or action_process_image_command_line contains "Invoke-WebRequest" or action_process_image_command_line contains " irm " or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "wget ")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "powershell_ise.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "://1" or action_process_image_command_line contains "://2" or action_process_image_command_line contains "://3" or action_process_image_command_line contains "://4" or action_process_image_command_line contains "://5" or action_process_image_command_line contains "://6" or action_process_image_command_line contains "://7" or action_process_image_command_line contains "://8" or action_process_image_command_line contains "://9")))
