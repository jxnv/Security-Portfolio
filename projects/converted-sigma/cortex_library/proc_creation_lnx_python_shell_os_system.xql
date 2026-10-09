// Title: Inline Python Execution - Spawn Shell Via OS System Library
// ID: 2d2f44ff-4611-4778-a8fc-323a0e9850cc
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.execution, attack.t1059
// Description: Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -c " and action_process_image_command_line contains "os.system(") and (action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/zsh")) and (((action_process_image_path endswith "/python" or action_process_image_path endswith "/python2" or action_process_image_path endswith "/python3")) or ((action_process_image_path contains "/python2." or action_process_image_path contains "/python3."))))
