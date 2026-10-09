// Title: Local System Accounts Discovery - Linux
// ID: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
// Status: test
// Level: low
// Author: Alejandro Ortuno, oscd.community, CheraghiMilad
// Date: 2020-10-08
// Tags: attack.discovery, attack.t1087.001
// Description: Detects enumeration of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/lastlog") or (action_process_image_command_line contains "'x:0:'") or ((action_process_image_path endswith "/cat" or action_process_image_path endswith "/ed" or action_process_image_path endswith "/head" or action_process_image_path endswith "/more" or action_process_image_path endswith "/nano" or action_process_image_path endswith "/tail" or action_process_image_path endswith "/vi" or action_process_image_path endswith "/vim" or action_process_image_path endswith "/less" or action_process_image_path endswith "/emacs" or action_process_image_path endswith "/sqlite3" or action_process_image_path endswith "/makemap") and (action_process_image_command_line contains "/etc/passwd" or action_process_image_command_line contains "/etc/shadow" or action_process_image_command_line contains "/etc/sudoers" or action_process_image_command_line contains "/etc/spwd.db" or action_process_image_command_line contains "/etc/pwd.db" or action_process_image_command_line contains "/etc/master.passwd")) or (action_process_image_path endswith "/id") or (action_process_image_path endswith "/lsof" and action_process_image_command_line contains "-u"))
