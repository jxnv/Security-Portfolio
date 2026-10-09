-- Title: Audit Rules Deleted Via Auditctl
-- ID: bed26dea-4525-47f4-b24a-76e30e44ffb0
-- Status: experimental
-- Level: high
-- Author: Mohamed LAKRI
-- Date: 2025-10-17
-- Tags: attack.defense-impairment, attack.t1685.004
-- Description: Detects the execution of 'auditctl' with the '-D' command line parameter, which deletes all configured audit rules and watches on Linux systems.
-- This technique is commonly used by attackers to disable audit logging and cover their tracks by removing monitoring capabilities.
-- Removal of audit rules can significantly impair detection of malicious activities on the affected system.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%/auditctl' AND REGEXP_LIKE(CommandLine, '-D'))
