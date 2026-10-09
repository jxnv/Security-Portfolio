-- Title: Potentially Suspicious CMD Shell Output Redirect
-- ID: 8e0bb260-d4b2-4fff-bb8d-3f82118e6892
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-12
-- Tags: attack.stealth, attack.t1218
-- Description: Detects inline Windows shell commands redirecting output via the ">" symbol to a suspicious location.
-- This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as "hostname" and "dir" to files for future exfiltration.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\cmd.exe') OR (OriginalFileName = 'Cmd.Exe')) AND (((CommandLine ILIKE '%>?%APPDATA%\\%' OR CommandLine ILIKE '%>?%TEMP%\\%' OR CommandLine ILIKE '%>?%TMP%\\%' OR CommandLine ILIKE '%>?%USERPROFILE%\\%' OR CommandLine ILIKE '%>?C:\\ProgramData\\%' OR CommandLine ILIKE '%>?C:\\Temp\\%' OR CommandLine ILIKE '%>?C:\\Users\\Public\\%' OR CommandLine ILIKE '%>?C:\\Windows\\Temp\\%')) OR ((CommandLine ILIKE '% >%' OR CommandLine ILIKE '%\">%' OR CommandLine ILIKE '%'>%') AND (CommandLine ILIKE '%C:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\%'))))
