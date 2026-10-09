-- Title: ETW Logging Disabled In .NET Processes - Sysmon Registry
-- ID: bf4fc428-dcc3-4bbd-99fe-2422aeee2544
-- Status: test
-- Level: high
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-06-05
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112, attack.t1685
-- Description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\COMPlus_ETWEnabled' OR TargetObject ILIKE '%\\COMPlus_ETWFlags') AND (Details = 0 OR Details = 'DWORD (0x00000000)')) OR (TargetObject ILIKE '%SOFTWARE\\Microsoft\\.NETFramework\\ETWEnabled' AND Details = 'DWORD (0x00000000)'))
