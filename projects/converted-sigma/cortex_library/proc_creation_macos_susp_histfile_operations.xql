// Title: Suspicious History File Operations
// ID: 508a9374-ad52-4789-b568-fc358def2c65
// Status: test
// Level: medium
// Author: Mikhail Larin, oscd.community
// Date: 2020-10-17
// Tags: attack.credential-access, attack.t1552.003
// Description: Detects commandline operations on shell history files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains ".bash_history" or action_process_image_command_line contains ".zsh_history" or action_process_image_command_line contains ".zhistory" or action_process_image_command_line contains ".history" or action_process_image_command_line contains ".sh_history" or action_process_image_command_line contains "fish_history"))
