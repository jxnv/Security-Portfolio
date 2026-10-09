// Title: VeeamBackup Database Credentials Dump Via Sqlcmd.EXE
// ID: b57ba453-b384-4ab9-9f40-1038086b4e53
// Status: test
// Level: high
// Author: frack113
// Date: 2021-12-20
// Tags: attack.collection, attack.t1005
// Description: Detects dump of credentials in VeeamBackup dbo
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "SELECT" and action_process_image_command_line contains "TOP" and action_process_image_command_line contains "[VeeamBackup].[dbo].[Credentials]")) and (action_process_image_path endswith "\\sqlcmd.exe"))
