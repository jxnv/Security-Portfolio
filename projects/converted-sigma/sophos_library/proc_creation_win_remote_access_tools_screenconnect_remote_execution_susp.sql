-- Title: Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution
-- ID: 7b582f1a-b318-4c6a-bf4e-66fe49bf55a5
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @Kostastsale
-- Date: 2022-02-25
-- Tags: attack.command-and-control, attack.t1219.002
-- Description: Detects potentially suspicious child processes launched via the ScreenConnect client service.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentCommandLine ILIKE '%:\\Windows\\TEMP\\ScreenConnect\\%' AND ParentCommandLine ILIKE '%run.cmd%') AND (Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\curl.exe' OR Image ILIKE '%\\dllhost.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\nltest.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wevtutil.exe'))
