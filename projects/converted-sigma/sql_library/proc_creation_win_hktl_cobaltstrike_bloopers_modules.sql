-- Title: Operator Bloopers Cobalt Strike Modules
-- ID: 4f154fb6-27d1-4813-a759-78b93e0b9c48
-- Status: test
-- Level: high
-- Author: _pete_0, TheDFIRReport
-- Date: 2022-05-06
-- Tags: attack.execution, attack.t1059.003
-- Description: Detects Cobalt Strike module/commands accidentally entered in CMD shell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Invoke-UserHunter%' OR CommandLine ILIKE '%Invoke-ShareFinder%' OR CommandLine ILIKE '%Invoke-Kerberoast%' OR CommandLine ILIKE '%Invoke-SMBAutoBrute%' OR CommandLine ILIKE '%Invoke-Nightmare%' OR CommandLine ILIKE '%zerologon%' OR CommandLine ILIKE '%av_query%')) AND ((OriginalFileName = 'Cmd.Exe') OR (Image ILIKE '%\\cmd.exe')))
