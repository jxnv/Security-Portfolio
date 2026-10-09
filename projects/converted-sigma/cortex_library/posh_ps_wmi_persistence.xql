// Title: Powershell WMI Persistence
// ID: 9e07f6e7-83aa-45c6-998e-0af26efd0a85
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-08-19
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.003
// Description: Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "New-CimInstance " and ScriptBlockText contains "-Namespace root/subscription " and ScriptBlockText contains "-ClassName __EventFilter " and ScriptBlockText contains "-Property ")) or ((ScriptBlockText contains "New-CimInstance " and ScriptBlockText contains "-Namespace root/subscription " and ScriptBlockText contains "-ClassName CommandLineEventConsumer " and ScriptBlockText contains "-Property ")))
