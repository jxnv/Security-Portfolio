// Title: Shell Invocation Via Ssh - Linux
// ID: 8737b7f6-8df3-4bb7-b1da-06019b99b687
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-08-29
// Tags: attack.execution, attack.t1059
// Description: Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/zsh" or action_process_image_command_line contains "sh 0<&2 1>&2" or action_process_image_command_line contains "sh 1>&2 0<&2")) and (action_process_image_path endswith "/ssh" and (action_process_image_command_line contains "ProxyCommand=;" or action_process_image_command_line contains "permitlocalcommand=yes" or action_process_image_command_line contains "localhost")))
