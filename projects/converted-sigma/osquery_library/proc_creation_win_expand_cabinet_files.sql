-- Title: Potentially Suspicious Cabinet File Expansion
-- ID: 9f107a84-532c-41af-b005-8d12a607639f
-- Status: test
-- Level: medium
-- Author: Bhabesh Raj, X__Junior (Nextron Systems)
-- Date: 2021-07-30
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\expand.exe" AND (CommandLine LIKE '%-F:%' OR CommandLine LIKE '%/F:%')) AND (((CommandLine LIKE '%:\\Perflogs\\%' OR CommandLine LIKE '%:\\ProgramData%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\Admin$\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%\\C$\\%' OR CommandLine LIKE '%\\Temporary Internet%')) OR (((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Favorites\\%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Favourites\\%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Contacts\\%')))) AND NOT ((ParentImage = 'C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe' AND CommandLine LIKE '%C:\\ProgramData\\Dell\\UpdateService\\Temp\\%')))
