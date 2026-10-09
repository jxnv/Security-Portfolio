// Title: System Restore Registry Modification via CommandLine
// ID: 7c06ab9b-b1d2-4ba9-b06e-09491ded20d9
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-03-11
// Tags: attack.impact, attack.t1490
// Description: Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " add " or action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "New-ItemProperty")) and ((action_process_image_command_line contains "DisableConfig" or action_process_image_command_line contains "DisableSR")) and ((action_process_image_command_line contains "\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" or action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))))
