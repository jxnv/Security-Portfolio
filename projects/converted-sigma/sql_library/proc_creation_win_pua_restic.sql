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

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%sftp:%' OR CommandLine ILIKE '%rest:http%' OR CommandLine ILIKE '%s3:s3.%' OR CommandLine ILIKE '%s3.http%' OR CommandLine ILIKE '%azure:%' OR CommandLine ILIKE '% gs:%' OR CommandLine ILIKE '%rclone:%' OR CommandLine ILIKE '%swift:%' OR CommandLine ILIKE '% b2:%') AND (CommandLine ILIKE '% init %' AND CommandLine ILIKE '% -r %')) OR (((CommandLine ILIKE '%--password-file%' AND CommandLine ILIKE '%init%' AND CommandLine ILIKE '% -r %')) OR ((CommandLine ILIKE '%--use-fs-snapshot%' AND CommandLine ILIKE '%backup%' AND CommandLine ILIKE '% -r %'))))
