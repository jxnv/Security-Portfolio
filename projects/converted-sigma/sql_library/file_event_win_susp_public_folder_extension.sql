-- Title: Suspicious Binaries and Scripts in Public Folder
-- ID: b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e
-- Status: experimental
-- Level: high
-- Author: The DFIR Report
-- Date: 2025-01-23
-- Tags: attack.execution, attack.t1204
-- Description: Detects the creation of a file with a suspicious extension in the public folder, which could indicate potential malicious activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetFilename ILIKE '%:\\Users\\Public\\%' AND (TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs'))
