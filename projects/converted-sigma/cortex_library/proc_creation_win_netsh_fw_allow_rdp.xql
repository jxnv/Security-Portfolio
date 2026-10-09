// Title: RDP Connection Allowed Via Netsh.EXE
// ID: 01aeb693-138d-49d2-9403-c4f52d7d3d62
// Status: test
// Level: high
// Author: Sander Wiebing
// Date: 2020-05-23
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects usage of the netsh command to open and allow connections to port 3389 (RDP). As seen used by Sarwent Malware
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "firewall " and action_process_image_command_line contains "add " and action_process_image_command_line contains "tcp " and action_process_image_command_line contains "3389") and (action_process_image_command_line contains "portopening" or action_process_image_command_line contains "allow")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
