// Title: Firewall Disabled via Netsh.EXE
// ID: 57c4bf16-227f-4394-8ec7-1b745ee061c3
// Status: test
// Level: medium
// Author: Fatih Sirin
// Date: 2019-11-01
// Tags: attack.defense-impairment, attack.t1686.003, attack.s0108
// Description: Detects netsh commands that turns off the Windows firewall
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")) and (((action_process_image_command_line contains "firewall" and action_process_image_command_line contains "set" and action_process_image_command_line contains "opmode" and action_process_image_command_line contains "disable")) or ((action_process_image_command_line contains "advfirewall" and action_process_image_command_line contains "set" and action_process_image_command_line contains "state" and action_process_image_command_line contains "off"))))
