// Title: Stop Windows Service Via PowerShell Stop-Service
// ID: c49c5062-0966-4170-9efd-9968c913a6cf
// Status: test
// Level: low
// Author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-05
// Tags: attack.impact, attack.t1489
// Description: Detects the stopping of a Windows service via the PowerShell Cmdlet "Stop-Service"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Stop-Service ") and (((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))))
