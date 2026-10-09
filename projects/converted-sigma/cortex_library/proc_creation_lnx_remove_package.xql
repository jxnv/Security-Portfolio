// Title: Linux Package Uninstall
// ID: 95d61234-7f56-465c-6f2d-b562c6fedbc4
// Status: test
// Level: low
// Author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-09
// Tags: attack.stealth, attack.t1070
// Description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/apt" or action_process_image_path endswith "/apt-get") and (action_process_image_command_line contains "remove" or action_process_image_command_line contains "purge")) or (action_process_image_path endswith "/dpkg" and (action_process_image_command_line contains "--remove " or action_process_image_command_line contains " -r ")) or (action_process_image_path endswith "/rpm" and action_process_image_command_line contains " -e ") or (action_process_image_path endswith "/yum" and (action_process_image_command_line contains "erase" or action_process_image_command_line contains "remove")))
