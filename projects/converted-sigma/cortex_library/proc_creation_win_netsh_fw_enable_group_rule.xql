// Title: Netsh Allow Group Policy on Microsoft Defender Firewall
// ID: 347906f3-e207-4d18-ae5b-a9403d6bcdef
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-09
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Adversaries may modify system firewalls in order to bypass controls limiting network usage
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "advfirewall" and action_process_image_command_line contains "firewall" and action_process_image_command_line contains "set" and action_process_image_command_line contains "rule" and action_process_image_command_line contains "group=" and action_process_image_command_line contains "new" and action_process_image_command_line contains "enable=Yes")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
