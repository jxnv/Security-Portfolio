// Title: Scheduled Task Executing Encoded Payload from Registry
// ID: c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport, X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-02-12
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
// Description: Detects the creation of a schtask that potentially executes a base64 encoded payload stored in the Windows Registry using PowerShell.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "/Create") and ((action_process_image_command_line contains "FromBase64String" or action_process_image_command_line contains "encodedcommand")) and ((action_process_image_command_line contains "Get-ItemProperty" or action_process_image_command_line contains " gp ")) and ((action_process_image_command_line contains "HKCU:" or action_process_image_command_line contains "HKLM:" or action_process_image_command_line contains "registry::" or action_process_image_command_line contains "HKEY_")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
