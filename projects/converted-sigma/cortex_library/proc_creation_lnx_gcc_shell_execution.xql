// Title: Shell Execution GCC  - Linux
// ID: 9b5de532-a757-4d70-946c-1f3e44f48b4d
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.discovery, attack.t1083
// Description: Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/bin/bash,-s" or action_process_image_command_line contains "/bin/dash,-s" or action_process_image_command_line contains "/bin/fish,-s" or action_process_image_command_line contains "/bin/sh,-s" or action_process_image_command_line contains "/bin/zsh,-s")) and ((action_process_image_path endswith "/c89" or action_process_image_path endswith "/c99" or action_process_image_path endswith "/gcc") and action_process_image_command_line contains "-wrapper"))
