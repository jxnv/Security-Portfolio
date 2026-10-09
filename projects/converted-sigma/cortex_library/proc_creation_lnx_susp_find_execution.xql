// Title: Potential Discovery Activity Using Find - Linux
// ID: 8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-28
// Tags: attack.discovery, attack.t1083
// Description: Detects usage of "find" binary in a suspicious manner to perform discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/find" and (action_process_image_command_line contains "-perm -4000" or action_process_image_command_line contains "-perm -2000" or action_process_image_command_line contains "-perm 0777" or action_process_image_command_line contains "-perm -222" or action_process_image_command_line contains "-perm -o w" or action_process_image_command_line contains "-perm -o x" or action_process_image_command_line contains "-perm -u=s" or action_process_image_command_line contains "-perm -g=s"))
