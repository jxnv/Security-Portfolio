// Title: Sensitive File Recovery From Backup Via Wbadmin.EXE
// ID: 84972c80-251c-4c3a-9079-4f00aad93938
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2024-05-10
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects the dump of highly sensitive files such as "NTDS.DIT" and "SECURITY" hive.
// Attackers can leverage the "wbadmin" utility in order to dump sensitive files that might contain credential or sensitive information.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " recovery" and action_process_image_command_line contains "recoveryTarget" and action_process_image_command_line contains "itemtype:File") and (action_process_image_command_line contains "\\config\\SAM" or action_process_image_command_line contains "\\config\\SECURITY" or action_process_image_command_line contains "\\config\\SYSTEM" or action_process_image_command_line contains "\\Windows\\NTDS\\NTDS.dit")) and ((action_process_image_path endswith "\\wbadmin.exe") or (action_process_image_name = "WBADMIN.EXE")))
