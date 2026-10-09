-- Title: Scheduled Task Executing Encoded Payload from Registry
-- ID: c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), @Kostastsale, TheDFIRReport, X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-02-12
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
-- Description: Detects the creation of a schtask that potentially executes a base64 encoded payload stored in the Windows Registry using PowerShell.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%/Create%') AND ((CommandLine LIKE '%FromBase64String%' OR CommandLine LIKE '%encodedcommand%')) AND ((CommandLine LIKE '%Get-ItemProperty%' OR CommandLine LIKE '% gp %')) AND ((CommandLine LIKE '%HKCU:%' OR CommandLine LIKE '%HKLM:%' OR CommandLine LIKE '%registry::%' OR CommandLine LIKE '%HKEY_%')) AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')))
