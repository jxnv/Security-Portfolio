// Title: Suspicious Download From Direct IP Via Bitsadmin
// ID: 99c840f2-2012-46fd-9141-c761987550ef
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-28
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003
// Description: Detects usage of bitsadmin downloading a file using an URL that contains an IP
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "://1" or action_process_image_command_line contains "://2" or action_process_image_command_line contains "://3" or action_process_image_command_line contains "://4" or action_process_image_command_line contains "://5" or action_process_image_command_line contains "://6" or action_process_image_command_line contains "://7" or action_process_image_command_line contains "://8" or action_process_image_command_line contains "://9")) and ((action_process_image_command_line contains " /transfer " or action_process_image_command_line contains " /create " or action_process_image_command_line contains " /addfile ")) and ((action_process_image_path endswith "\\bitsadmin.exe") or (action_process_image_name = "bitsadmin.exe"))) and not ((action_process_image_command_line contains "://7-")))
