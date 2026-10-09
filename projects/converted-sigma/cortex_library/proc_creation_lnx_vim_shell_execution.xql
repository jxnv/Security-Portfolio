// Title: Vim GTFOBin Abuse - Linux
// ID: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
// Date: 2022-12-28
// Tags: attack.execution, attack.discovery, attack.t1059, attack.t1083
// Description: Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
// Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ":!/" or action_process_image_command_line contains ":!$" or action_process_image_command_line contains ":!.." or action_process_image_command_line contains ":lua " or action_process_image_command_line contains ":py " or action_process_image_command_line contains ":shell" or action_process_image_command_line contains "/bin/bash" or action_process_image_command_line contains "/bin/dash" or action_process_image_command_line contains "/bin/fish" or action_process_image_command_line contains "/bin/sh" or action_process_image_command_line contains "/bin/csh" or action_process_image_command_line contains "/bin/ksh" or action_process_image_command_line contains "/bin/zsh" or action_process_image_command_line contains "/bin/tmux")) and ((action_process_image_path endswith "/rvim" or action_process_image_path endswith "/vi" or action_process_image_path endswith "/vim" or action_process_image_path endswith "/vimdiff") and (action_process_image_command_line contains " --cmd " or action_process_image_command_line contains " -c")))
