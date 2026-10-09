// Title: Suspicious Eventlog Clearing or Configuration Change Activity
// ID: cc36992a-4671-4f21-a91d-6c2b72a2edf5
// Status: stable
// Level: high
// Author: Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2019-09-26
// Tags: attack.defense-impairment, attack.t1685.005, attack.t1685.001, car.2016-04-002
// Description: Detects the clearing or configuration tampering of EventLog using utilities such as "wevtutil", "powershell" and "wmic".
// This technique were seen used by threat actors and ransomware strains in order to evade defenses.
// Converted by: Sigma Universal SIEM/EDR CLI

(((((CommandLine contains "clear-log " OR CommandLine contains " cl " OR CommandLine contains "set-log " OR CommandLine contains " sl " OR CommandLine contains "lfn:")) AND ((Image="*\\wevtutil.exe") OR (OriginalFileName == "wevtutil.exe"))) OR ((((CommandLine contains "Clear-EventLog " OR CommandLine contains "Remove-EventLog " OR CommandLine contains "Limit-EventLog " OR CommandLine contains "Clear-WinEvent ")) OR ((CommandLine contains "Eventing.Reader.EventLogSession" AND CommandLine contains "ClearLog")) OR ((CommandLine contains "Diagnostics.EventLog" AND CommandLine contains "Clear"))) AND ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe"))) OR ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe" OR Image="*\\wmic.exe") AND CommandLine contains "ClearEventLog")) AND NOT (((ParentImage == "C:\\Windows\\SysWOW64\\msiexec.exe" OR ParentImage == "C:\\Windows\\System32\\msiexec.exe") AND CommandLine contains " sl ")))
