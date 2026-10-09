// Title: Suspicious Mstsc.EXE Execution With Local RDP File
// ID: 6e22722b-dfb1-4508-a911-49ac840b40f8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-18
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith ".rdp" or action_process_image_command_line endswith ".rdp\"")) and ((action_process_image_path endswith "\\mstsc.exe") or (action_process_image_name = "mstsc.exe")) and ((action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\System32\\spool\\drivers\\color" or action_process_image_command_line contains ":\\Windows\\System32\\Tasks_Migrated " or action_process_image_command_line contains ":\\Windows\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains ":\\Windows\\Tracing\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\Downloads\\")))
