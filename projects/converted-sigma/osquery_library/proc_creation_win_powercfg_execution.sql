-- Title: Suspicious Powercfg Execution To Change Lock Screen Timeout
-- ID: f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-11-18
-- Tags: attack.stealth
-- Description: Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\powercfg.exe") OR (OriginalFileName = 'PowerCfg.exe')) AND (((CommandLine LIKE '%/setacvalueindex %' AND CommandLine LIKE '%SCHEME_CURRENT%' AND CommandLine LIKE '%SUB_VIDEO%' AND CommandLine LIKE '%VIDEOCONLOCK%')) OR ((CommandLine LIKE '%-change %' AND CommandLine LIKE '%-standby-timeout-%'))))
