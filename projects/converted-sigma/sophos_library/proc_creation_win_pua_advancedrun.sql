-- Title: PUA - AdvancedRun Execution
-- ID: d2b749ee-4225-417e-b20e-a8d2193cbb84
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-20
-- Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1564.003, attack.t1134.002, attack.t1059.003
-- Description: Detects the execution of AdvancedRun utility
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((OriginalFileName = 'AdvancedRun.exe') OR ((CommandLine ILIKE '% /EXEFilename %' AND CommandLine ILIKE '% /Run%')) OR ((CommandLine ILIKE '% /WindowState 0%' AND CommandLine ILIKE '% /RunAs %' AND CommandLine ILIKE '% /CommandLine %')))
