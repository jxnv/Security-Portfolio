-- Title: Powershell Create Scheduled Task
-- ID: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((ScriptBlockText ILIKE '%Invoke-CimMethod%' AND ScriptBlockText ILIKE '%-ClassName%' AND ScriptBlockText ILIKE '%PS_ScheduledTask%' AND ScriptBlockText ILIKE '%-NameSpace%' AND ScriptBlockText ILIKE '%Root\\Microsoft\\Windows\\TaskScheduler%')) OR ((ScriptBlockText ILIKE '%New-ScheduledTaskAction%' OR ScriptBlockText ILIKE '%New-ScheduledTaskTrigger%' OR ScriptBlockText ILIKE '%New-ScheduledTaskPrincipal%' OR ScriptBlockText ILIKE '%New-ScheduledTaskSettingsSet%' OR ScriptBlockText ILIKE '%New-ScheduledTask%' OR ScriptBlockText ILIKE '%Register-ScheduledTask%'))) AND NOT (((ScriptBlockText ILIKE '%Microsoft.PowerShell.Core\\Export-ModuleMember%' AND ScriptBlockText ILIKE '%Microsoft.Management.Infrastructure.CimInstance%' AND ScriptBlockText ILIKE '%__cmdletization_methodParameter%'))))
