-- Title: Registry Hive File Staged Outside Standard User Profile Path
-- ID: a7f3c891-2e4d-4b6a-9f8c-d5e2a1b04c73
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-07-23
-- Tags: attack.privilege-escalation, attack.t1548, attack.credential-access, attack.t1003
-- Description: Detects the creation of a registry hive file (UsrClass.dat or NTUSER.DAT) outside of the standard user profile path.
-- These files generally contain various user-specific registry settings and are typically located in the user's profile directory.
-- Staging these files outside of the standard path can be indicative of an attacker attempting to manipulate user registry settings
-- for persistence, privilege escalation, or dump user registry hives for credential harvesting.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%\\UsrClass.dat' OR TargetFilename ILIKE '%\\NTUSER.DAT')) AND NOT (((REGEXP_LIKE(TargetFilename, '^C:\\Users\\[^\\]+\\NTUSER\.DAT$')) OR ((TargetFilename ILIKE 'C:\\Windows\\System32\\config\\%' OR TargetFilename ILIKE 'C:\\Windows\\SYSVOL\\%' OR TargetFilename ILIKE 'C:\\Windows\\ServiceProfiles\\%')) OR (TargetFilename ILIKE '%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat'))))
