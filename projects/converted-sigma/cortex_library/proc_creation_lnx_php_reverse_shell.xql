// Title: Potential PHP Reverse Shell
// ID: c6714a24-d7d5-4283-a36b-3ffd091d5f7e
// Status: test
// Level: high
// Author: @d4ns4n_
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects usage of the PHP CLI with the "-r" flag which allows it to run inline PHP code. The rule looks for calls to the "fsockopen" function which allows the creation of sockets.
// Attackers often leverage this in combination with functions such as "exec" or "fopen" to initiate a reverse shell connection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path contains "/php" and (action_process_image_command_line contains " -r " and action_process_image_command_line contains "fsockopen") and (action_process_image_command_line contains "ash" or action_process_image_command_line contains "bash" or action_process_image_command_line contains "bsh" or action_process_image_command_line contains "csh" or action_process_image_command_line contains "ksh" or action_process_image_command_line contains "pdksh" or action_process_image_command_line contains "sh" or action_process_image_command_line contains "tcsh" or action_process_image_command_line contains "zsh"))
