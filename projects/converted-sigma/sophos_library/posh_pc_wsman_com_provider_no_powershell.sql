-- Title: Suspicious Non PowerShell WSMAN COM Provider
-- ID: df9a0e0e-fedb-4d6c-8668-d765dfc92aa7
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-06-24
-- Tags: attack.execution, attack.t1059.001, attack.lateral-movement, attack.t1021.003
-- Description: Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Data ILIKE '%ProviderName=WSMan%') AND NOT (((REGEXP_LIKE(Data, 'HostId=[a-zA-Z0-9-]{36}\s+EngineVersion=')) OR ((Data ILIKE '%HostApplication=powershell%' OR Data ILIKE '%HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell%' OR Data ILIKE '%HostApplication=C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell%' OR Data ILIKE '%HostApplication=C:/Windows/System32/WindowsPowerShell/v1.0/powershell%' OR Data ILIKE '%HostApplication=C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell%')))) AND NOT ((Data ILIKE '%HostApplication=C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe%')))
