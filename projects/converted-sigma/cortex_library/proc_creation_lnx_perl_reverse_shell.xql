// Title: Potential Perl Reverse Shell Execution
// ID: 259df6bc-003f-4306-9f54-4ff1a08fa38e
// Status: test
// Level: high
// Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "fdopen(" and action_process_image_command_line contains "::Socket::INET")) or ((action_process_image_command_line contains "Socket" and action_process_image_command_line contains "connect" and action_process_image_command_line contains "open" and action_process_image_command_line contains "exec"))) and (action_process_image_path endswith "/perl" and action_process_image_command_line contains " -e "))
