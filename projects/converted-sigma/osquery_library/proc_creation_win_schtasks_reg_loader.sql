-- Title: Scheduled Task Executing Payload from Registry
-- ID: 86588b36-c6d3-465f-9cee-8f9093e07798
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-18
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
-- Description: Detects the creation of a schtasks that potentially executes a payload stored in the Windows Registry using PowerShell.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/Create%') AND ((CommandLine LIKE '%Get-ItemProperty%' OR CommandLine LIKE '% gp %')) AND ((CommandLine LIKE '%HKCU:%' OR CommandLine LIKE '%HKLM:%' OR CommandLine LIKE '%registry::%' OR CommandLine LIKE '%HKEY_%')) AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe'))) AND NOT (((CommandLine LIKE '%FromBase64String%' OR CommandLine LIKE '%encodedcommand%'))))
