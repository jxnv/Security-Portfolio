-- Title: PowerShell Called from an Executable Version Mismatch
-- ID: c70e019b-1479-4b65-b0cc-cd0c6093a599
-- Status: test
-- Level: high
-- Author: Sean Metcalf (source), Florian Roth (Nextron Systems)
-- Date: 2017-03-05
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects PowerShell called from an executable by the version mismatch method
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Data ILIKE '%EngineVersion=2.%' OR Data ILIKE '%EngineVersion=4.%' OR Data ILIKE '%EngineVersion=5.%')) AND (Data ILIKE '%HostVersion=3.%'))
