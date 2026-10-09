-- Title: Modify Group Policy Settings - ScriptBlockLogging
-- ID: b7216a7d-687e-4c8d-82b1-3080b2ad961f
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-19
-- Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
-- Description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%GroupPolicyRefreshTimeDC%' OR ScriptBlockText ILIKE '%GroupPolicyRefreshTimeOffsetDC%' OR ScriptBlockText ILIKE '%GroupPolicyRefreshTime%' OR ScriptBlockText ILIKE '%GroupPolicyRefreshTimeOffset%' OR ScriptBlockText ILIKE '%EnableSmartScreen%' OR ScriptBlockText ILIKE '%ShellSmartScreenLevel%')) AND (ScriptBlockText ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\System%'))
