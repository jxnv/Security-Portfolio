-- Title: Powershell WMI Persistence
-- ID: 9e07f6e7-83aa-45c6-998e-0af26efd0a85
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-08-19
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.003
-- Description: Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%New-CimInstance %' AND ScriptBlockText ILIKE '%-Namespace root/subscription %' AND ScriptBlockText ILIKE '%-ClassName __EventFilter %' AND ScriptBlockText ILIKE '%-Property %')) OR ((ScriptBlockText ILIKE '%New-CimInstance %' AND ScriptBlockText ILIKE '%-Namespace root/subscription %' AND ScriptBlockText ILIKE '%-ClassName CommandLineEventConsumer %' AND ScriptBlockText ILIKE '%-Property %')))
