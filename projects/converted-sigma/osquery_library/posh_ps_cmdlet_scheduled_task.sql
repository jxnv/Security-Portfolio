-- Title: Powershell Create Scheduled Task
-- ID: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((ScriptBlockText LIKE '%Invoke-CimMethod%' AND ScriptBlockText LIKE '%-ClassName%' AND ScriptBlockText LIKE '%PS_ScheduledTask%' AND ScriptBlockText LIKE '%-NameSpace%' AND ScriptBlockText LIKE '%Root\\Microsoft\\Windows\\TaskScheduler%')) OR ((ScriptBlockText LIKE '%New-ScheduledTaskAction%' OR ScriptBlockText LIKE '%New-ScheduledTaskTrigger%' OR ScriptBlockText LIKE '%New-ScheduledTaskPrincipal%' OR ScriptBlockText LIKE '%New-ScheduledTaskSettingsSet%' OR ScriptBlockText LIKE '%New-ScheduledTask%' OR ScriptBlockText LIKE '%Register-ScheduledTask%'))) AND NOT (((ScriptBlockText LIKE '%Microsoft.PowerShell.Core\\Export-ModuleMember%' AND ScriptBlockText LIKE '%Microsoft.Management.Infrastructure.CimInstance%' AND ScriptBlockText LIKE '%__cmdletization_methodParameter%'))))
