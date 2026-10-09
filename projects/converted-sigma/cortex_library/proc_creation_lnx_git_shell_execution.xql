// Title: Shell Execution via Git - Linux
// ID: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.execution, attack.t1059
// Description: Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "/git" and (actor_process_command_line contains " -p " and actor_process_command_line contains "help") and (action_process_image_command_line contains "bash 0<&1" or action_process_image_command_line contains "dash 0<&1" or action_process_image_command_line contains "sh 0<&1"))
