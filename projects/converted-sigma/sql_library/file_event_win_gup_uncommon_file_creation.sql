-- Title: Uncommon File Created by Notepad++ Updater Gup.EXE
-- ID: 3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-02-03
-- Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
-- Description: Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations.
-- This could indicate potential exploitation of the updater component to deliver unwanted malware or unwarranted files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\gup.exe') AND NOT ((((TargetFilename ILIKE 'C:\\Program Files\\Notepad++\\%' OR TargetFilename ILIKE 'C:\\Program Files (x86)\\Notepad++\\%')) OR (((TargetFilename ILIKE '%\\plugins\\JsonTools\\testfiles\\%' OR TargetFilename ILIKE '%\\Notepad++\\plugins\\ComparePlugin\\%')) OR ((TargetFilename ILIKE '%npp.%' AND TargetFilename ILIKE '%.portable.%' AND TargetFilename ILIKE '%\\plugins\\%'))) OR (TargetFilename ILIKE 'C:\\$Recycle.Bin\\S-1-5-21%') OR (TargetFilename ILIKE 'C:\\Users\\%' AND (TargetFilename ILIKE '%\\AppData\\Local\\Temp\\%' AND TargetFilename ILIKE '%.zip%')) OR (TargetFilename ILIKE 'C:\\Users\\%' AND (TargetFilename ILIKE '%\\AppData\\Local\\Temp\\%' AND TargetFilename ILIKE '%npp.%' AND TargetFilename ILIKE '%.Installer.%' AND TargetFilename ILIKE '%.exe%')))))
