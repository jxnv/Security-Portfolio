-- Title: Malicious ShellIntel PowerShell Commandlets
-- ID: 402e1e1d-ad59-47b6-bf80-1ee44985b3a7
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
-- Date: 2021-08-09
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects Commandlet names from ShellIntel exploitation scripts.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%Invoke-SMBAutoBrute%' OR ScriptBlockText ILIKE '%Invoke-GPOLinks%' OR ScriptBlockText ILIKE '%Invoke-Potato%'))
