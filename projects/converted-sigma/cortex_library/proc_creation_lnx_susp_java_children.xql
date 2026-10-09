// Title: Suspicious Java Children Processes
// ID: d292e0af-9a18-420c-9525-ec0ac3936892
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-03
// Tags: attack.execution, attack.t1059
// Description: Detects java process spawning suspicious children
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "/java" and (action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "bash" or action_process_image_command_line contains "dash" or action_process_image_command_line contains "ksh" or action_process_image_command_line contains "zsh" or action_process_image_command_line contains "csh" or action_process_image_command_line contains "fish" or action_process_image_command_line contains "curl" or action_process_image_command_line contains "wget" or action_process_image_command_line contains "python"))
