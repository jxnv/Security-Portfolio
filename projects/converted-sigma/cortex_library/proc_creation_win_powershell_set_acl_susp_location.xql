// Title: PowerShell Set-Acl On Windows Folder
// ID: 0944e002-e3f6-4eb5-bf69-3a3067b53d73
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.stealth
// Description: Detects PowerShell scripts to set the ACL to a file in the Windows folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Set-Acl " and action_process_image_command_line contains "-AclObject ")) and (((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))) and ((action_process_image_command_line contains "-Path \"C:\\Windows" or action_process_image_command_line contains "-Path 'C:\\Windows" or action_process_image_command_line contains "-Path %windir%" or action_process_image_command_line contains "-Path $env:windir")) and ((action_process_image_command_line contains "FullControl" or action_process_image_command_line contains "Allow")))
