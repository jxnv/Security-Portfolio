// Title: Firewall Configuration Discovery Via Netsh.EXE
// ID: 0e4164da-94bc-450d-a7be-a4b176179f1f
// Status: test
// Level: low
// Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
// Date: 2021-12-07
// Tags: attack.discovery, attack.t1016
// Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "netsh" and action_process_image_command_line contains "show " and action_process_image_command_line contains "firewall ") and (action_process_image_command_line contains "config " or action_process_image_command_line contains "state " or action_process_image_command_line contains "rule " or action_process_image_command_line contains "name=all")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
