// Title: Veeam Backup Database Suspicious Query
// ID: 696bfb54-227e-4602-ac5b-30d9d2053312
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.collection, attack.t1005
// Description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "BackupRepositories" or action_process_image_command_line contains "Backups" or action_process_image_command_line contains "Credentials" or action_process_image_command_line contains "HostCreds" or action_process_image_command_line contains "SmbFileShares" or action_process_image_command_line contains "Ssh_creds" or action_process_image_command_line contains "VSphereInfo")) and (action_process_image_path endswith "\\sqlcmd.exe" and (action_process_image_command_line contains "VeeamBackup" and action_process_image_command_line contains "From ")))
