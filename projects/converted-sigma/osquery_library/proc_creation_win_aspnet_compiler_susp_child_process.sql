-- Title: Suspicious Child Process of AspNetCompiler
-- ID: 9ccba514-7cb6-4c5c-b377-700758f2f120
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-14
-- Tags: attack.execution, attack.stealth, attack.t1127
-- Description: Detects potentially suspicious child processes of "aspnet_compiler.exe".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\calc.exe" OR Image="*\\notepad.exe")) OR ((Image LIKE '%\\Users\\Public\\%' OR Image LIKE '%\\AppData\\Local\\Temp\\%' OR Image LIKE '%\\AppData\\Local\\Roaming\\%' OR Image LIKE '%:\\Temp\\%' OR Image LIKE '%:\\Windows\\Temp\\%' OR Image LIKE '%:\\Windows\\System32\\Tasks\\%' OR Image LIKE '%:\\Windows\\Tasks\\%'))) AND (ParentImage="*\\aspnet_compiler.exe"))
