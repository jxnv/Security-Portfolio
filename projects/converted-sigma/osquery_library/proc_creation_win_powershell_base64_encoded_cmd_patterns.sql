-- Title: Suspicious PowerShell Encoded Command Patterns
-- ID: b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-05-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '% JAB%' OR CommandLine LIKE '% SUVYI%' OR CommandLine LIKE '% SQBFAFgA%' OR CommandLine LIKE '% aWV4I%' OR CommandLine LIKE '% IAB%' OR CommandLine LIKE '% PAA%' OR CommandLine LIKE '% aQBlAHgA%')) AND ((CommandLine LIKE '% -e %' OR CommandLine LIKE '% -en %' OR CommandLine LIKE '% -enc %' OR CommandLine LIKE '% -enco%')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.Exe' OR OriginalFileName = 'pwsh.dll')))) AND NOT (((ParentImage LIKE '%C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%' OR ParentImage LIKE '%\\gc_worker.exe%'))))
