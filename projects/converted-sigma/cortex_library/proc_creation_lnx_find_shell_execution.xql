// Title: Shell Execution via Find - Linux
// ID: 6adfbf8f-52be-4444-9bac-81b539624146
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.discovery, attack.t1083
// Description: Detects the use of the find command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or exploitation attempt.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/zsh")) and (action_process_image_path endswith "/find" and (action_process_image_command_line contains " . " and action_process_image_command_line contains "-exec")))
