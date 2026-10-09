// Title: RDP Port Forwarding Rule Added Via Netsh.EXE
// ID: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), oscd.community
// Date: 2019-01-29
// Tags: attack.lateral-movement, attack.command-and-control, attack.t1090
// Description: Detects the execution of netsh to configure a port forwarding of port 3389 (RDP) rule
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " i" and action_process_image_command_line contains " p" and action_process_image_command_line contains "=3389" and action_process_image_command_line contains " c")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
