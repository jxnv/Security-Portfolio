-- Title: PUA - Restic Backup Tool Execution
-- ID: 6ddff2e8-ea1a-45d0-8938-93dfc1d67ae7
-- Status: experimental
-- Level: high
-- Author: Nounou Mbeiri, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-10-17
-- Tags: attack.exfiltration, attack.t1048, attack.t1567.002
-- Description: Detects the execution of the Restic backup tool, which can be used for data exfiltration.
-- Threat actors may leverage Restic to back up and exfiltrate sensitive data to remote storage locations, including cloud services.
-- If not legitimately used in the enterprise environment, its presence may indicate malicious activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%sftp:%' OR CommandLine LIKE '%rest:http%' OR CommandLine LIKE '%s3:s3.%' OR CommandLine LIKE '%s3.http%' OR CommandLine LIKE '%azure:%' OR CommandLine LIKE '% gs:%' OR CommandLine LIKE '%rclone:%' OR CommandLine LIKE '%swift:%' OR CommandLine LIKE '% b2:%') AND (CommandLine LIKE '% init %' AND CommandLine LIKE '% -r %')) OR (((CommandLine LIKE '%--password-file%' AND CommandLine LIKE '%init%' AND CommandLine LIKE '% -r %')) OR ((CommandLine LIKE '%--use-fs-snapshot%' AND CommandLine LIKE '%backup%' AND CommandLine LIKE '% -r %'))))
