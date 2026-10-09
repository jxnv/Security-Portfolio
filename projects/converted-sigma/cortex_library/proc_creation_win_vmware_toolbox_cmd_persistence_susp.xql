// Title: Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script
// ID: 236d8e89-ed95-4789-a982-36f4643738ba
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-14
// Tags: attack.execution, attack.persistence, attack.t1059
// Description: Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script that's located in a potentially suspicious location to run for a specific VM state
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " script " and action_process_image_command_line contains " set ")) and ((action_process_image_path endswith "\\VMwareToolBoxCmd.exe") or (action_process_image_name = "toolbox-cmd.exe")) and ((action_process_image_command_line contains ":\\PerfLogs\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Windows\\System32\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp")))
