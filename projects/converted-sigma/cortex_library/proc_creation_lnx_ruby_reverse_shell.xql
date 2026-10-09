// Title: Potential Ruby Reverse Shell
// ID: b8bdac18-c06e-4016-ac30-221553e74f59
// Status: test
// Level: medium
// Author: @d4ns4n_
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path contains "ruby" and (action_process_image_command_line contains " -e" and action_process_image_command_line contains "rsocket" and action_process_image_command_line contains "TCPSocket") and (action_process_image_command_line contains " ash" or action_process_image_command_line contains " bash" or action_process_image_command_line contains " bsh" or action_process_image_command_line contains " csh" or action_process_image_command_line contains " ksh" or action_process_image_command_line contains " pdksh" or action_process_image_command_line contains " sh" or action_process_image_command_line contains " tcsh"))
