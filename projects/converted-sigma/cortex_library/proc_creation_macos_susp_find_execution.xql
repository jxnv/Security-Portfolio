// Title: Potential Discovery Activity Using Find - MacOS
// ID: 85de3a19-b675-4a51-bfc6-b11a5186c971
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-28
// Tags: attack.discovery, attack.t1083
// Description: Detects usage of "find" binary in a suspicious manner to perform discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/find" and (action_process_image_command_line contains "-perm -4000" or action_process_image_command_line contains "-perm -2000" or action_process_image_command_line contains "-perm 0777" or action_process_image_command_line contains "-perm -222" or action_process_image_command_line contains "-perm -o w" or action_process_image_command_line contains "-perm -o x" or action_process_image_command_line contains "-perm -u=s" or action_process_image_command_line contains "-perm -g=s"))
