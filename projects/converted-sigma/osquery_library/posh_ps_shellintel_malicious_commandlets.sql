-- Title: Malicious ShellIntel PowerShell Commandlets
-- ID: 402e1e1d-ad59-47b6-bf80-1ee44985b3a7
-- Status: test
-- Level: high
-- Author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
-- Date: 2021-08-09
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects Commandlet names from ShellIntel exploitation scripts.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%Invoke-SMBAutoBrute%' OR ScriptBlockText LIKE '%Invoke-GPOLinks%' OR ScriptBlockText LIKE '%Invoke-Potato%'))
