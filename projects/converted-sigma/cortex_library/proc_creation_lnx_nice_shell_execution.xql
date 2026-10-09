// Title: Shell Execution via Nice - Linux
// ID: 093d68c7-762a-42f4-9f46-95e79142571a
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.discovery, attack.t1083
// Description: Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/nice" and (action_process_image_command_line endswith "/bin/bash" or action_process_image_command_line endswith "/bin/dash" or action_process_image_command_line endswith "/bin/fish" or action_process_image_command_line endswith "/bin/sh" or action_process_image_command_line endswith "/bin/zsh"))
