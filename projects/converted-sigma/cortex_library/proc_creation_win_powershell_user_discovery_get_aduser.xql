// Title: User Discovery And Export Via Get-ADUser Cmdlet
// ID: 1114e048-b69c-4f41-bc20-657245ae6e3f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.discovery, attack.t1033
// Description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Get-ADUser " and action_process_image_command_line contains " -Filter \\*") and (action_process_image_command_line contains " > " or action_process_image_command_line contains " | Select " or action_process_image_command_line contains "Out-File" or action_process_image_command_line contains "Set-Content" or action_process_image_command_line contains "Add-Content")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
