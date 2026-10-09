// Title: PowerShell Script Change Permission Via Set-Acl
// ID: bdeb2cff-af74-4094-8426-724dc937f20a
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.stealth
// Description: Detects PowerShell execution to set the ACL of a file or a folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Set-Acl " and action_process_image_command_line contains "-AclObject " and action_process_image_command_line contains "-Path ")) and (((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))))
