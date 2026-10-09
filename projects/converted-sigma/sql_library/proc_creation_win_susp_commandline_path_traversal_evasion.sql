-- Title: Potential Command Line Path Traversal Evasion Attempt
-- ID: 1327381e-6ab0-4f38-b583-4c1b8346a56b
-- Status: test
-- Level: medium
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-10-26
-- Tags: attack.stealth, attack.t1036
-- Description: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\Windows\\%' AND (CommandLine ILIKE '%\\..\\Windows\\%' OR CommandLine ILIKE '%\\..\\System32\\%' OR CommandLine ILIKE '%\\..\\..\\%')) OR (CommandLine ILIKE '%.exe\\..\\%')) AND NOT (((CommandLine ILIKE '%\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\..\\%') OR (CommandLine ILIKE '%\\Google\\Drive\\googledrivesync.exe\\..\\%'))))
