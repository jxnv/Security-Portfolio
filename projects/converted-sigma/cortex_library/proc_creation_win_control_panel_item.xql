// Title: Control Panel Items
// ID: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
// Status: test
// Level: high
// Author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
// Date: 2020-06-22
// Tags: attack.privilege-escalation, attack.execution, attack.stealth, attack.t1218.002, attack.persistence, attack.t1546
// Description: Detects the malicious use of a control panel item
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "add" and action_process_image_command_line contains "CurrentVersion\\Control Panel\\CPLs")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe"))) or ((action_process_image_command_line endswith ".cpl") and not ((((action_process_image_command_line contains "regsvr32 " and action_process_image_command_line contains " /s " and action_process_image_command_line contains "igfxCPL.cpl")) or ((action_process_image_command_line contains "\\System32\\" or action_process_image_command_line contains "%System%" or action_process_image_command_line contains "|C:\\Windows\\system32|"))))))
