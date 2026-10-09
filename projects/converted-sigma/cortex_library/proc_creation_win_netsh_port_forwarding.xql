// Title: New Port Forwarding Rule Added Via Netsh.EXE
// ID: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), omkar72, oscd.community, Swachchhanda Shrawan Poudel
// Date: 2019-01-29
// Tags: attack.lateral-movement, attack.command-and-control, attack.t1090
// Description: Detects the execution of netsh commands that configure a new port forwarding (PortProxy) rule
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")) and (((action_process_image_command_line contains "interface" and action_process_image_command_line contains "portproxy" and action_process_image_command_line contains "add" and action_process_image_command_line contains "v4tov4")) or ((action_process_image_command_line contains "i " and action_process_image_command_line contains "p " and action_process_image_command_line contains "a " and action_process_image_command_line contains "v ")) or ((action_process_image_command_line contains "connectp" and action_process_image_command_line contains "listena" and action_process_image_command_line contains "c="))))
