// Title: Shell Execution via Rsync - Linux
// ID: e2326866-609f-4015-aea9-7ec634e8aa04
// Status: experimental
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
// Date: 2024-09-02
// Tags: attack.execution, attack.t1059
// Description: Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/ash " or action_process_image_command_line contains "/bash " or action_process_image_command_line contains "/dash " or action_process_image_command_line contains "/csh " or action_process_image_command_line contains "/sh " or action_process_image_command_line contains "/zsh " or action_process_image_command_line contains "/tcsh " or action_process_image_command_line contains "/ksh " or action_process_image_command_line contains "'ash " or action_process_image_command_line contains "'bash " or action_process_image_command_line contains "'dash " or action_process_image_command_line contains "'csh " or action_process_image_command_line contains "'sh " or action_process_image_command_line contains "'zsh " or action_process_image_command_line contains "'tcsh " or action_process_image_command_line contains "'ksh ")) and ((action_process_image_path endswith "/rsync" or action_process_image_path endswith "/rsyncd") and action_process_image_command_line contains " -e "))
