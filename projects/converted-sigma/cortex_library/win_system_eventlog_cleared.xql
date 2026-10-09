// Title: Eventlog Cleared
// ID: a62b37e0-45d3-48d9-a517-90c1a1b0186b
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-01-10
// Tags: attack.defense-impairment, attack.t1685.005, car.2016-04-002
// Description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 104 and Provider_Name = "Microsoft-Windows-Eventlog") and not (((Channel = "Microsoft-Windows-PowerShell/Operational" or Channel = "Microsoft-Windows-Sysmon/Operational" or Channel = "PowerShellCore/Operational" or Channel = "Security" or Channel = "System" or Channel = "Windows PowerShell"))))
