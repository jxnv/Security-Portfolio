-- Title: Suspicious File Created in Outlook Temporary Directory
-- ID: fabb0e80-030c-4e3e-a104-d09676991ac3
-- Status: experimental
-- Level: high
-- Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-07-22
-- Tags: attack.initial-access, attack.t1566.001
-- Description: Detects the creation of files with suspicious file extensions in the temporary directory that Outlook uses when opening attachments.
-- This can be used to detect spear-phishing campaigns that use suspicious files as attachments, which may contain malicious code.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%.cpl' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.iso' OR TargetFilename ILIKE '%.rdp' OR TargetFilename ILIKE '%.svg' OR TargetFilename ILIKE '%.vba' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs')) AND (((TargetFilename ILIKE '%\\AppData\\Local\\Packages\\Microsoft.Outlook_%' OR TargetFilename ILIKE '%\\AppData\\Local\\Microsoft\\Olk\\Attachments\\%')) OR ((TargetFilename ILIKE '%\\AppData\\Local\\Microsoft\\Windows\\%' AND TargetFilename ILIKE '%\\Content.Outlook\\%'))))
