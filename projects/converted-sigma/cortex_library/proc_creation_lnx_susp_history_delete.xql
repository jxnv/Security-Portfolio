// Title: History File Deletion
// ID: 1182f3b3-e716-4efa-99ab-d2685d04360f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.impact, attack.t1565.001
// Description: Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/rm" or action_process_image_path endswith "/unlink" or action_process_image_path endswith "/shred")) and (((action_process_image_command_line contains "/.bash_history" or action_process_image_command_line contains "/.zsh_history")) or ((action_process_image_command_line endswith "_history" or action_process_image_command_line endswith ".history" or action_process_image_command_line endswith "zhistory"))))
