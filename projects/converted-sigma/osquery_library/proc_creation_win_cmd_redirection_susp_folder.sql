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

SELECT * FROM processes WHERE (((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe')) AND (((CommandLine LIKE '%>?%APPDATA%\\%' OR CommandLine LIKE '%>?%TEMP%\\%' OR CommandLine LIKE '%>?%TMP%\\%' OR CommandLine LIKE '%>?%USERPROFILE%\\%' OR CommandLine LIKE '%>?C:\\ProgramData\\%' OR CommandLine LIKE '%>?C:\\Temp\\%' OR CommandLine LIKE '%>?C:\\Users\\Public\\%' OR CommandLine LIKE '%>?C:\\Windows\\Temp\\%')) OR ((CommandLine LIKE '% >%' OR CommandLine LIKE '%\">%' OR CommandLine LIKE '%'>%') AND (CommandLine LIKE '%C:\\Users\\%' AND CommandLine LIKE '%\\AppData\\Local\\%'))))
