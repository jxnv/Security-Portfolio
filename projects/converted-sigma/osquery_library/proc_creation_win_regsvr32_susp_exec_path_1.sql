-- Title: Regsvr32 Execution From Potential Suspicious Location
-- ID: 9525dc73-0327-438c-8c04-13c0e037e9da
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-26
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects execution of regsvr32 where the DLL is located in a potentially suspicious location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%:\\ProgramData\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%')) AND ((Image="*\\regsvr32.exe") OR (OriginalFileName = 'REGSVR32.EXE')))
