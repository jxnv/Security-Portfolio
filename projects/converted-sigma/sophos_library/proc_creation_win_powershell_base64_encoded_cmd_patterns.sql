-- Title: Suspicious PowerShell Encoded Command Patterns
-- ID: b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-05-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '% JAB%' OR CommandLine ILIKE '% SUVYI%' OR CommandLine ILIKE '% SQBFAFgA%' OR CommandLine ILIKE '% aWV4I%' OR CommandLine ILIKE '% IAB%' OR CommandLine ILIKE '% PAA%' OR CommandLine ILIKE '% aQBlAHgA%')) AND ((CommandLine ILIKE '% -e %' OR CommandLine ILIKE '% -en %' OR CommandLine ILIKE '% -enc %' OR CommandLine ILIKE '% -enco%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.Exe' OR OriginalFileName = 'pwsh.dll')))) AND NOT (((ParentImage ILIKE '%C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%' OR ParentImage ILIKE '%\\gc_worker.exe%'))))
