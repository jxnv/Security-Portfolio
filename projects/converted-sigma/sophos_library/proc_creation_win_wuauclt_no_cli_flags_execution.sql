-- Title: Suspicious Windows Update Agent Empty Cmdline
-- ID: 52d097e2-063e-4c9c-8fbb-855c8948d135
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-26
-- Tags: attack.stealth, attack.t1036
-- Description: Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%Wuauclt' OR CommandLine ILIKE '%Wuauclt.exe')) AND ((Image ILIKE '%\\Wuauclt.exe') OR (OriginalFileName = 'Wuauclt.exe')))
