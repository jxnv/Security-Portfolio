// Title: Suspicious Service DACL Modification Via Set-Service Cmdlet
// ID: a95b9b42-1308-4735-a1af-abb1c5e6f5ac
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
// Description: Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\pwsh.exe") or (action_process_image_name = "pwsh.dll")) and ((action_process_image_command_line contains "-SecurityDescriptorSddl " or action_process_image_command_line contains "-sd ")) and ((action_process_image_command_line contains "Set-Service " and action_process_image_command_line contains "D;;") and (action_process_image_command_line contains ";;;IU" or action_process_image_command_line contains ";;;SU" or action_process_image_command_line contains ";;;BA" or action_process_image_command_line contains ";;;SY" or action_process_image_command_line contains ";;;WD")))
