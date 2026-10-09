// Title: ETW Logging Disabled In .NET Processes - Registry
// ID: a4c90ea1-2634-4ca0-adbb-35eae169b6fc
// Status: test
// Level: high
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-06-05
// Tags: attack.persistence, attack.defense-impairment, attack.t1112, attack.t1685
// Description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4657 and ObjectName contains "\\Environment" and (ObjectValueName = "COMPlus_ETWEnabled" or ObjectValueName = "COMPlus_ETWFlags") and NewValue = 0) or (EventID = 4657 and ObjectName endswith "\\SOFTWARE\\Microsoft\\.NETFramework" and ObjectValueName = "ETWEnabled" and NewValue = 0))
