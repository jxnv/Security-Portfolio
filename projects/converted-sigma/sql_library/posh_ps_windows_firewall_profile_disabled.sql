-- Title: Windows Firewall Profile Disabled
-- ID: 488b44e7-3781-4a71-888d-c95abfacf44d
-- Status: test
-- Level: medium
-- Author: Austin Songer @austinsonger
-- Date: 2021-10-12
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detects when a user disables the Windows Firewall via a Profile to help evade defense.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%Set-NetFirewallProfile %' AND ScriptBlockText ILIKE '% -Enabled %' AND ScriptBlockText ILIKE '% False%')) AND ((ScriptBlockText ILIKE '% -All %' OR ScriptBlockText ILIKE '%Public%' OR ScriptBlockText ILIKE '%Domain%' OR ScriptBlockText ILIKE '%Private%')))
