// Title: Suspicious Eventlog Clear
// ID: 0f017df3-8f5a-414f-ad6b-24aff1128278
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-09-12
// Tags: attack.defense-impairment, attack.t1685.005
// Description: Detects usage of known powershell cmdlets such as "Clear-EventLog" to clear the Windows event logs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "Clear-EventLog " or ScriptBlockText contains "Remove-EventLog " or ScriptBlockText contains "Limit-EventLog " or ScriptBlockText contains "Clear-WinEvent ")) or ((ScriptBlockText contains "Eventing.Reader.EventLogSession" and ScriptBlockText contains "ClearLog")) or ((ScriptBlockText contains "Diagnostics.EventLog" and ScriptBlockText contains "Clear")))
