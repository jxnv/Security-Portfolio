// Title: Unsigned AppX Installation Attempt Using Add-AppxPackage
// ID: 37651c2a-42cd-4a69-ae0d-22a4349aa04a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-31
// Tags: attack.persistence, attack.stealth
// Description: Detects usage of the "Add-AppxPackage" or it's alias "Add-AppPackage" to install unsigned AppX packages
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Add-AppPackage " or action_process_image_command_line contains "Add-AppxPackage ")) and (action_process_image_command_line contains " -AllowUnsigned") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
