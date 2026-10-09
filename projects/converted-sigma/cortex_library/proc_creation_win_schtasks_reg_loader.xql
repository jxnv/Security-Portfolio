// Title: Scheduled Task Executing Payload from Registry
// ID: 86588b36-c6d3-465f-9cee-8f9093e07798
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-18
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
// Description: Detects the creation of a schtasks that potentially executes a payload stored in the Windows Registry using PowerShell.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/Create") and ((action_process_image_command_line contains "Get-ItemProperty" or action_process_image_command_line contains " gp ")) and ((action_process_image_command_line contains "HKCU:" or action_process_image_command_line contains "HKLM:" or action_process_image_command_line contains "registry::" or action_process_image_command_line contains "HKEY_")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe"))) and not (((action_process_image_command_line contains "FromBase64String" or action_process_image_command_line contains "encodedcommand"))))
