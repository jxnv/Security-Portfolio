// Title: Potential PsExec Remote Execution
// ID: ea011323-7045-460b-b2d7-0f7442ea6b38
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-28
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "accepteula" and action_process_image_command_line contains " -u " and action_process_image_command_line contains " -p " and action_process_image_command_line contains " \\\\\\\\")) and not (((action_process_image_command_line contains "\\\\\\\\localhost" or action_process_image_command_line contains "\\\\\\\\127."))))
