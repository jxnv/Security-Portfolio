-- Title: Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script
-- ID: c1337eb8-921a-4b59-855b-4ba188ddcc42
-- Status: test
-- Level: high
-- Author: Tim Rauch, frack113
-- Date: 2022-09-20
-- Tags: attack.impact, attack.t1490
-- Description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%.Delete()%' OR ScriptBlockText ILIKE '%Remove-WmiObject%' OR ScriptBlockText ILIKE '%rwmi%' OR ScriptBlockText ILIKE '%Remove-CimInstance%' OR ScriptBlockText ILIKE '%rcim%')) AND ((ScriptBlockText ILIKE '%Get-WmiObject%' OR ScriptBlockText ILIKE '%gwmi%' OR ScriptBlockText ILIKE '%Get-CimInstance%' OR ScriptBlockText ILIKE '%gcim%')) AND (ScriptBlockText ILIKE '%Win32_ShadowCopy%'))
