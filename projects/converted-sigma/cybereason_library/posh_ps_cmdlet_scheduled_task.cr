// Title: Powershell Create Scheduled Task
// ID: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-28
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
// Converted by: Sigma Universal SIEM/EDR CLI

((((ScriptBlockText contains "Invoke-CimMethod" AND ScriptBlockText contains "-ClassName" AND ScriptBlockText contains "PS_ScheduledTask" AND ScriptBlockText contains "-NameSpace" AND ScriptBlockText contains "Root\\Microsoft\\Windows\\TaskScheduler")) OR ((ScriptBlockText contains "New-ScheduledTaskAction" OR ScriptBlockText contains "New-ScheduledTaskTrigger" OR ScriptBlockText contains "New-ScheduledTaskPrincipal" OR ScriptBlockText contains "New-ScheduledTaskSettingsSet" OR ScriptBlockText contains "New-ScheduledTask" OR ScriptBlockText contains "Register-ScheduledTask"))) AND NOT (((ScriptBlockText contains "Microsoft.PowerShell.Core\\Export-ModuleMember" AND ScriptBlockText contains "Microsoft.Management.Infrastructure.CimInstance" AND ScriptBlockText contains "__cmdletization_methodParameter"))))
