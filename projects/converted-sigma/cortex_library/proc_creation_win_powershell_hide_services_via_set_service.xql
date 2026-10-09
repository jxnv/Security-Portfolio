// Title: Abuse of Service Permissions to Hide Services Via Set-Service
// ID: 514e4c3a-c77d-4cde-a00f-046425e2301e
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-17
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
// Description: Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-SecurityDescriptorSddl " or action_process_image_command_line contains "-sd ")) and ((action_process_image_path endswith "\\pwsh.exe") or (action_process_image_name = "pwsh.dll")) and ((action_process_image_command_line contains "Set-Service " and action_process_image_command_line contains "DCLCWPDTSD")))
