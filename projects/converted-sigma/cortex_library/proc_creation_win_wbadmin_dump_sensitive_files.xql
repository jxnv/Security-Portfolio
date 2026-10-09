// Title: Sensitive File Dump Via Wbadmin.EXE
// ID: 8b93a509-1cb8-42e1-97aa-ee24224cdc15
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2024-05-10
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects the dump of highly sensitive files such as "NTDS.DIT" and "SECURITY" hive.
// Attackers can leverage the "wbadmin" utility in order to dump sensitive files that might contain credential or sensitive information.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "start" or action_process_image_command_line contains "backup")) and ((action_process_image_path endswith "\\wbadmin.exe") or (action_process_image_name = "WBADMIN.EXE")) and ((action_process_image_command_line contains "\\config\\SAM" or action_process_image_command_line contains "\\config\\SECURITY" or action_process_image_command_line contains "\\config\\SYSTEM" or action_process_image_command_line contains "\\Windows\\NTDS\\NTDS.dit")))
