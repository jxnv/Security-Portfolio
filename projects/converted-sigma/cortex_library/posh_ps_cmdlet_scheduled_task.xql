// Title: Powershell Create Scheduled Task
// ID: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-28
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((ScriptBlockText contains "Invoke-CimMethod" and ScriptBlockText contains "-ClassName" and ScriptBlockText contains "PS_ScheduledTask" and ScriptBlockText contains "-NameSpace" and ScriptBlockText contains "Root\\Microsoft\\Windows\\TaskScheduler")) or ((ScriptBlockText contains "New-ScheduledTaskAction" or ScriptBlockText contains "New-ScheduledTaskTrigger" or ScriptBlockText contains "New-ScheduledTaskPrincipal" or ScriptBlockText contains "New-ScheduledTaskSettingsSet" or ScriptBlockText contains "New-ScheduledTask" or ScriptBlockText contains "Register-ScheduledTask"))) and not (((ScriptBlockText contains "Microsoft.PowerShell.Core\\Export-ModuleMember" and ScriptBlockText contains "Microsoft.Management.Infrastructure.CimInstance" and ScriptBlockText contains "__cmdletization_methodParameter"))))
