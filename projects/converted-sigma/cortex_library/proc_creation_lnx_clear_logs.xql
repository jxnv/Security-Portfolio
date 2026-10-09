// Title: Linux Logs Clearing Attempts
// ID: 80915f59-9b56-4616-9de0-fd0dea6c12fe
// Status: stable
// Level: medium
// Author: Ömer Günal, oscd.community
// Date: 2020-10-07
// Tags: attack.defense-impairment, attack.t1685.006
// Description: Detects logs clearing attempts on Linux systems via utilities such as 'rm', 'rmdir', 'shred', and 'unlink' targeting log files and directories.
// Adversaries often try to clear logs to cover their tracks after performing malicious activities.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/rm" or action_process_image_path endswith "/rmdir" or action_process_image_path endswith "/shred" or action_process_image_path endswith "/unlink") and (action_process_image_command_line contains "/var/log" or action_process_image_command_line contains "/var/spool/mail")) and not (((action_process_image_path endswith "/rm" and action_process_image_command_line startswith "rm -f -- /var/log//dmesg") or (action_process_image_path endswith "/rm" and action_process_image_command_line startswith "rm -f /var/log/sysstat/"))))
