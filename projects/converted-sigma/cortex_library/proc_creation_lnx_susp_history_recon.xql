// Title: Print History File Contents
// ID: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.reconnaissance, attack.t1592.004
// Description: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/cat" or action_process_image_path endswith "/head" or action_process_image_path endswith "/tail" or action_process_image_path endswith "/more")) and (((action_process_image_command_line contains "/.bash_history" or action_process_image_command_line contains "/.zsh_history")) or ((action_process_image_command_line endswith "_history" or action_process_image_command_line endswith ".history" or action_process_image_command_line endswith "zhistory"))))
