-- Title: Potentially Suspicious Cabinet File Expansion
-- ID: 9f107a84-532c-41af-b005-8d12a607639f
-- Status: test
-- Level: medium
-- Author: Bhabesh Raj, X__Junior (Nextron Systems)
-- Date: 2021-07-30
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\expand.exe' AND (CommandLine ILIKE '%-F:%' OR CommandLine ILIKE '%/F:%')) AND (((CommandLine ILIKE '%:\\Perflogs\\%' OR CommandLine ILIKE '%:\\ProgramData%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\Admin$\\%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%\\AppData\\Roaming\\%' OR CommandLine ILIKE '%\\C$\\%' OR CommandLine ILIKE '%\\Temporary Internet%')) OR (((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Favorites\\%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Favourites\\%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Contacts\\%')))) AND NOT ((ParentImage = 'C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe' AND CommandLine ILIKE '%C:\\ProgramData\\Dell\\UpdateService\\Temp\\%')))
