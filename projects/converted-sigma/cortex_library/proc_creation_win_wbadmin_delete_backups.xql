// Title: Windows Backup Deleted Via Wbadmin.EXE
// ID: 89f75308-5b1b-4390-b2d8-d6b2340efaf8
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-13
// Tags: attack.impact, attack.t1490
// Description: Detects the deletion of backups or system state backups via "wbadmin.exe".
// This technique is used by numerous ransomware families and actors.
// This may only be successful on server platforms that have Windows Backup enabled.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "delete " and action_process_image_command_line contains "backup")) and ((action_process_image_path endswith "\\wbadmin.exe") or (action_process_image_name = "WBADMIN.EXE"))) and not ((action_process_image_command_line contains "keepVersions:0")))
