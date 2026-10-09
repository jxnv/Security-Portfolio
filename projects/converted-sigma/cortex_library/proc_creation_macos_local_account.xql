// Title: Local System Accounts Discovery - MacOs
// ID: ddf36b67-e872-4507-ab2e-46bda21b842c
// Status: test
// Level: low
// Author: Alejandro Ortuno, oscd.community
// Date: 2020-10-08
// Tags: attack.discovery, attack.t1087.001
// Description: Detects enumeration of local system accounts on MacOS systems.
// This can be used by attackers to identify accounts for lateral movement or privilege escalation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/dscacheutil" and (action_process_image_command_line contains "-q" and action_process_image_command_line contains "user")) or (action_process_image_path endswith "/dscl" and (action_process_image_command_line contains "list" and action_process_image_command_line contains "/users")) or (action_process_image_path endswith "/ls" and (action_process_image_command_line endswith "/Users" or action_process_image_command_line endswith "/Users'" or action_process_image_command_line endswith "/Users\"")) or (action_process_image_path endswith "/id") or ((action_process_image_path endswith "/who" or action_process_image_path endswith "/w" or action_process_image_path endswith "/users" or action_process_image_path endswith "/last")) or ((action_process_image_path endswith "/defaults" or action_process_image_path endswith "/plutil") and action_process_image_command_line contains "com.apple.loginwindow") or (action_process_image_path endswith "/lsof" and action_process_image_command_line contains "-u") or ((action_process_image_path endswith "/cat" or action_process_image_path endswith "/awk" or action_process_image_path endswith "/grep") and (action_process_image_command_line contains "/etc/passwd" or action_process_image_command_line contains "/etc/sudoers")) or (action_process_image_command_line contains "'*:0:'"))
