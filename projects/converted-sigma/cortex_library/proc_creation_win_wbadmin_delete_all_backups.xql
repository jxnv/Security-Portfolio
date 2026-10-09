// Title: All Backups Deleted Via Wbadmin.EXE
// ID: 639c9081-f482-47d3-a0bd-ddee3d4ecd76
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-13
// Tags: attack.impact, attack.t1490
// Description: Detects the deletion of all backups or system state backups via "wbadmin.exe".
// This technique is used by numerous ransomware families and actors.
// This may only be successful on server platforms that have Windows Backup enabled.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "delete" and action_process_image_command_line contains "backup") and action_process_image_command_line contains "keepVersions:0") and ((action_process_image_path endswith "\\wbadmin.exe") or (action_process_image_name = "WBADMIN.EXE")))
