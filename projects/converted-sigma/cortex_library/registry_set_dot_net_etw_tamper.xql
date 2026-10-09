// Title: ETW Logging Disabled In .NET Processes - Sysmon Registry
// ID: bf4fc428-dcc3-4bbd-99fe-2422aeee2544
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-06-05
// Tags: attack.persistence, attack.defense-impairment, attack.t1112, attack.t1685
// Description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject endswith "\\COMPlus_ETWEnabled" or TargetObject endswith "\\COMPlus_ETWFlags") and (Details = 0 or Details = "DWORD (0x00000000)")) or (TargetObject endswith "SOFTWARE\\Microsoft\\.NETFramework\\ETWEnabled" and Details = "DWORD (0x00000000)"))
