// Title: Service StartupType Change Via PowerShell Set-Service
// ID: 62b20d44-1546-4e61-afce-8e175eb9473c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-04
// Tags: attack.execution, attack.defense-impairment, attack.t1685
// Description: Detects the use of the PowerShell "Set-Service" cmdlet to change the startup type of a service to "disabled" or "manual"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Set-Service" and action_process_image_command_line contains "-StartupType") and (action_process_image_command_line contains "Disabled" or action_process_image_command_line contains "Manual")) and ((action_process_image_path endswith "\\powershell.exe") or (action_process_image_name = "PowerShell.EXE")))
