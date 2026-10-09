// Title: Service Registry Key Deleted Via Reg.EXE
// ID: 05b2aa93-1210-42c8-8d9a-2fcc13b284f5
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects execution of "reg.exe" commands with the "delete" flag on services registry key. Often used by attacker to remove AV software services
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " delete ") and ((action_process_image_path endswith "reg.exe") or (action_process_image_name = "reg.exe")) and (action_process_image_command_line contains "\\SYSTEM\\CurrentControlSet\\services\\"))
