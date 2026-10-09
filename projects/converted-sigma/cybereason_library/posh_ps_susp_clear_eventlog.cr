// Title: Suspicious Eventlog Clear
// ID: 0f017df3-8f5a-414f-ad6b-24aff1128278
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-09-12
// Tags: attack.defense-impairment, attack.t1685.005
// Description: Detects usage of known powershell cmdlets such as "Clear-EventLog" to clear the Windows event logs
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains "Clear-EventLog " OR ScriptBlockText contains "Remove-EventLog " OR ScriptBlockText contains "Limit-EventLog " OR ScriptBlockText contains "Clear-WinEvent ")) OR ((ScriptBlockText contains "Eventing.Reader.EventLogSession" AND ScriptBlockText contains "ClearLog")) OR ((ScriptBlockText contains "Diagnostics.EventLog" AND ScriptBlockText contains "Clear")))
