// Title: Shell Invocation via Env Command - Linux
// ID: bed978f8-7f3a-432b-82c5-9286a9b3031a
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.execution, attack.t1059.004
// Description: Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/env" and (action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/zsh"))
