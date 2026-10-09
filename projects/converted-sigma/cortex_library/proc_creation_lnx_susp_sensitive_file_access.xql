// Title: Potential Suspicious Change To Sensitive/Critical Files
// ID: 86157017-c2b1-4d4a-8c33-93b8e67e4af4
// Status: test
// Level: medium
// Author: @d4ns4n_ (Wuerth-Phoenix)
// Date: 2023-05-30
// Tags: attack.impact, attack.t1565.001
// Description: Detects changes of sensitive and critical files. Monitors files that you don't expect to change without planning on Linux system.
// These files include, but are not limited to, system configuration files, authentication files, and critical application files.
// Attackers often target these files to maintain persistence, escalate privileges, or disrupt system operations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/cat" or action_process_image_path endswith "/echo" or action_process_image_path endswith "/grep" or action_process_image_path endswith "/head" or action_process_image_path endswith "/more" or action_process_image_path endswith "/tail") and action_process_image_command_line contains ">") or ((action_process_image_path endswith "/emacs" or action_process_image_path endswith "/nano" or action_process_image_path endswith "/sed" or action_process_image_path endswith "/vi" or action_process_image_path endswith "/vim"))) and ((action_process_image_command_line contains "/bin/login" or action_process_image_command_line contains "/bin/passwd" or action_process_image_command_line contains "/boot/" or action_process_image_command_line contains "/etc/*.conf" or action_process_image_command_line contains "/etc/cron." or action_process_image_command_line contains "/etc/crontab" or action_process_image_command_line contains "/etc/hosts" or action_process_image_command_line contains "/etc/init.d" or action_process_image_command_line contains "/etc/sudoers" or action_process_image_command_line contains "/opt/bin/" or action_process_image_command_line contains "/sbin" or action_process_image_command_line contains "/usr/bin/" or action_process_image_command_line contains "/usr/local/bin/")) and not (1=1))
