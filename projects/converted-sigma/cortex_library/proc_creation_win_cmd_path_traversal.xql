// Title: Potential CommandLine Path Traversal Via Cmd.EXE
// ID: 087790e3-3287-436c-bccf-cbd0184a7db1
// Status: test
// Level: high
// Author: xknow @xknow_infosec, Tim Shelton
// Date: 2020-06-11
// Tags: attack.execution, attack.t1059.003
// Description: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((actor_process_command_line contains "/c" or actor_process_command_line contains "/k" or actor_process_command_line contains "/r")) or ((action_process_image_command_line contains "/c" or action_process_image_command_line contains "/k" or action_process_image_command_line contains "/r"))) and ((actor_process_image_path endswith "\\cmd.exe") or (action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "cmd.exe")) and ((actor_process_command_line = "/../../") or (action_process_image_command_line contains "/../../"))) and not ((action_process_image_command_line contains "\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java")))
