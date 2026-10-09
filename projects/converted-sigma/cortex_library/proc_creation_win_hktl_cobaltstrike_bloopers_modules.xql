// Title: Operator Bloopers Cobalt Strike Modules
// ID: 4f154fb6-27d1-4813-a759-78b93e0b9c48
// Status: test
// Level: high
// Author: _pete_0, TheDFIRReport
// Date: 2022-05-06
// Tags: attack.execution, attack.t1059.003
// Description: Detects Cobalt Strike module/commands accidentally entered in CMD shell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Invoke-UserHunter" or action_process_image_command_line contains "Invoke-ShareFinder" or action_process_image_command_line contains "Invoke-Kerberoast" or action_process_image_command_line contains "Invoke-SMBAutoBrute" or action_process_image_command_line contains "Invoke-Nightmare" or action_process_image_command_line contains "zerologon" or action_process_image_command_line contains "av_query")) and ((action_process_image_name = "Cmd.Exe") or (action_process_image_path endswith "\\cmd.exe")))
