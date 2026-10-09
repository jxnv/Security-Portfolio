// Title: Add Windows Capability Via PowerShell Cmdlet
// ID: b36d01a3-ddaf-4804-be18-18a6247adfcd
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-22
// Tags: attack.execution
// Description: Detects usage of the "Add-WindowsCapability" cmdlet to add Windows capabilities. Notable capabilities could be "OpenSSH" and others.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "OpenSSH.") and (action_process_image_command_line contains "Add-WindowsCapability") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
