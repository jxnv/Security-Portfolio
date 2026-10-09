// Title: Suspicious PowerShell Encoded Command Patterns
// ID: b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-05-24
// Tags: attack.execution, attack.t1059.001
// Description: Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " JAB" or action_process_image_command_line contains " SUVYI" or action_process_image_command_line contains " SQBFAFgA" or action_process_image_command_line contains " aWV4I" or action_process_image_command_line contains " IAB" or action_process_image_command_line contains " PAA" or action_process_image_command_line contains " aQBlAHgA")) and ((action_process_image_command_line contains " -e " or action_process_image_command_line contains " -en " or action_process_image_command_line contains " -enc " or action_process_image_command_line contains " -enco")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.Exe" or action_process_image_name = "pwsh.dll")))) and not (((actor_process_image_path contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or actor_process_image_path contains "\\gc_worker.exe"))))
