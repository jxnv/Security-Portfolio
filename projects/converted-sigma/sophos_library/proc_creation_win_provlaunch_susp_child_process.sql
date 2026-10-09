-- Title: Suspicious Provlaunch.EXE Child Process
-- ID: f9999590-1f94-4a34-a91e-951e47bedefd
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-08
-- Tags: attack.stealth, attack.t1218
-- Description: Detects suspicious child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((Image ILIKE '%:\\PerfLogs\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%\\AppData\\Temp\\%' OR Image ILIKE '%\\Windows\\System32\\Tasks\\%' OR Image ILIKE '%\\Windows\\Tasks\\%' OR Image ILIKE '%\\Windows\\Temp\\%'))) AND (ParentImage ILIKE '%\\provlaunch.exe'))
