// Title: System Information Discovery via Registry Queries
// ID: 0022869c-49f7-4ff2-ba03-85ac42ddac58
// Status: experimental
// Level: low
// Author: lazarg
// Date: 2025-06-12
// Tags: attack.discovery, attack.t1082
// Description: Detects attempts to query system information directly from the Windows Registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "Get-ItemPropertyValue" or action_process_image_command_line contains "gpv")) or (action_process_image_path endswith "\\reg.exe" and action_process_image_command_line contains "query" and (action_process_image_command_line contains "-v" or action_process_image_command_line contains "/v"))) and ((action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows Defender" or action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" or action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" or action_process_image_command_line contains "\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" or action_process_image_command_line contains "\\SYSTEM\\CurrentControlSet\\Services")))
