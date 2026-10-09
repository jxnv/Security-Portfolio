-- Title: Suspicious Child Process of AspNetCompiler
-- ID: 9ccba514-7cb6-4c5c-b377-700758f2f120
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-14
-- Tags: attack.execution, attack.stealth, attack.t1127
-- Description: Detects potentially suspicious child processes of "aspnet_compiler.exe".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\notepad.exe')) OR ((Image ILIKE '%\\Users\\Public\\%' OR Image ILIKE '%\\AppData\\Local\\Temp\\%' OR Image ILIKE '%\\AppData\\Local\\Roaming\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%:\\Windows\\Temp\\%' OR Image ILIKE '%:\\Windows\\System32\\Tasks\\%' OR Image ILIKE '%:\\Windows\\Tasks\\%'))) AND (ParentImage ILIKE '%\\aspnet_compiler.exe'))
