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

(((CommandLine contains "sftp:" OR CommandLine contains "rest:http" OR CommandLine contains "s3:s3." OR CommandLine contains "s3.http" OR CommandLine contains "azure:" OR CommandLine contains " gs:" OR CommandLine contains "rclone:" OR CommandLine contains "swift:" OR CommandLine contains " b2:") AND (CommandLine contains " init " AND CommandLine contains " -r ")) OR (((CommandLine contains "--password-file" AND CommandLine contains "init" AND CommandLine contains " -r ")) OR ((CommandLine contains "--use-fs-snapshot" AND CommandLine contains "backup" AND CommandLine contains " -r "))))
