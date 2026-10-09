// Title: Suspicious Invocation of Shell via AWK - Linux
// ID: 8c1a5675-cb85-452f-a298-b01b22a51856
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.execution, attack.t1059
// Description: Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
// This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/zsh")) and ((action_process_image_path endswith "/awk" or action_process_image_path endswith "/gawk" or action_process_image_path endswith "/mawk" or action_process_image_path endswith "/nawk") and action_process_image_command_line contains "BEGIN {system"))
