// Title: Deny Service Access Using Security Descriptor Tampering Via Sc.EXE
// ID: 99cf1e02-00fb-4c0d-8375-563f978dfd37
// Status: test
// Level: high
// Author: Jonhnathan Ribeiro, oscd.community
// Date: 2020-10-16
// Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
// Description: Detects suspicious DACL modifications to deny access to a service that affects critical trustees. This can be used to hide services or make them unstoppable.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\sc.exe") or (action_process_image_name = "sc.exe")) and ((action_process_image_command_line contains "sdset" and action_process_image_command_line contains "D;")) and ((action_process_image_command_line contains ";IU" or action_process_image_command_line contains ";SU" or action_process_image_command_line contains ";BA" or action_process_image_command_line contains ";SY" or action_process_image_command_line contains ";WD")))
