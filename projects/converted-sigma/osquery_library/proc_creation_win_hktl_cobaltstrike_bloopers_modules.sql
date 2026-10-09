-- Title: Operator Bloopers Cobalt Strike Modules
-- ID: 4f154fb6-27d1-4813-a759-78b93e0b9c48
-- Status: test
-- Level: high
-- Author: _pete_0, TheDFIRReport
-- Date: 2022-05-06
-- Tags: attack.execution, attack.t1059.003
-- Description: Detects Cobalt Strike module/commands accidentally entered in CMD shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Invoke-UserHunter%' OR CommandLine LIKE '%Invoke-ShareFinder%' OR CommandLine LIKE '%Invoke-Kerberoast%' OR CommandLine LIKE '%Invoke-SMBAutoBrute%' OR CommandLine LIKE '%Invoke-Nightmare%' OR CommandLine LIKE '%zerologon%' OR CommandLine LIKE '%av_query%')) AND ((OriginalFileName = 'Cmd.Exe') OR (Image="*\\cmd.exe")))
