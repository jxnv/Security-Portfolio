// Title: Windows EventLog Autologger Session Registry Modification Via CommandLine
// ID: d7b81144-b866-48a4-9bcc-275dc69d870e
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-12-25
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects attempts to disable Windows EventLog autologger sessions via registry modification.
// The AutoLogger event tracing session records events that occur early in the operating system boot process.
// Applications and device drivers can use the AutoLogger session to capture traces before the user logs in.
// Adversaries may disable these sessions to evade detection and prevent security monitoring of early boot activities and system events.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add " or action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains "si ")) and (action_process_image_command_line contains "\\Control\\WMI\\Autologger\\") and ((action_process_image_command_line contains "Start" or action_process_image_command_line contains "Enabled")) and (((action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "reg.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
