// Title: Suspicious Invoke-WebRequest Execution
// ID: 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-02
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "curl " or action_process_image_command_line contains "Invoke-WebRequest" or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "wget ")) and ((action_process_image_command_line contains " -ur" or action_process_image_command_line contains " -o")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "powershell_ise.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and ((action_process_image_command_line contains "\\AppData\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Temp\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "%AppData%" or action_process_image_command_line contains "%Public%" or action_process_image_command_line contains "%Temp%" or action_process_image_command_line contains "%tmp%" or action_process_image_command_line contains ":\\Windows\\")))
