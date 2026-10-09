// Title: PUA - Restic Backup Tool Execution
// ID: 6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7
// Status: experimental
// Level: high
// Author: Nounou Mbeiri, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-10-17
// Tags: attack.exfiltration, attack.t1048, attack.t1567.002
// Description: Detects the execution of the Restic backup tool, which can be used for data exfiltration.
// Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services.
// If not legitimately used in the enterprise environment, its presence may indicate malicious activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "sftp:" or action_process_image_command_line contains "rest:http" or action_process_image_command_line contains "s3:s3." or action_process_image_command_line contains "s3.http" or action_process_image_command_line contains "azure:" or action_process_image_command_line contains " gs:" or action_process_image_command_line contains "rclone:" or action_process_image_command_line contains "swift:" or action_process_image_command_line contains " b2:") and (action_process_image_command_line contains " init " and action_process_image_command_line contains " -r ")) or (((action_process_image_command_line contains "--password-file" and action_process_image_command_line contains "init" and action_process_image_command_line contains " -r ")) or ((action_process_image_command_line contains "--use-fs-snapshot" and action_process_image_command_line contains "backup" and action_process_image_command_line contains " -r "))))
