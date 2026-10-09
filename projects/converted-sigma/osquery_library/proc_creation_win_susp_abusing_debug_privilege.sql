-- Title: Abused Debug Privilege by Arbitrary Parent Processes
-- ID: d522eca2-2973-4391-a3e0-ef0374321dae
-- Status: test
-- Level: high
-- Author: Semanur Guneysu @semanurtg, oscd.community
-- Date: 2020-10-28
-- Tags: attack.privilege-escalation, attack.t1548
-- Description: Detection of unusual child processes by different system processes
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'Cmd.Exe'))) AND ((ParentImage="*\\winlogon.exe" OR ParentImage="*\\services.exe" OR ParentImage="*\\lsass.exe" OR ParentImage="*\\csrss.exe" OR ParentImage="*\\smss.exe" OR ParentImage="*\\wininit.exe" OR ParentImage="*\\spoolsv.exe" OR ParentImage="*\\searchindexer.exe") AND (User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%'))) AND NOT (((CommandLine LIKE '% route %' AND CommandLine LIKE '% ADD %'))))
