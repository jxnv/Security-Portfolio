// Title: Interactive Bash Suspicious Children
// ID: ea3ecad2-db86-4a89-ad0b-132a10d2db55
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-14
// Tags: attack.execution, attack.stealth, attack.t1059.004, attack.t1036
// Description: Detects suspicious interactive bash as a parent to rather uncommon child processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_command_line = "bash -i") and (((action_process_image_command_line contains "-c import " or action_process_image_command_line contains "base64" or action_process_image_command_line contains "pty.spawn")) or ((action_process_image_path endswith "whoami" or action_process_image_path endswith "iptables" or action_process_image_path endswith "/ncat" or action_process_image_path endswith "/nc" or action_process_image_path endswith "/netcat"))))
