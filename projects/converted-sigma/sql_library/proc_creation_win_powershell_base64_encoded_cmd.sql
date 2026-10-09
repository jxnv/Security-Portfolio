-- Title: Suspicious Encoded PowerShell Command Line
-- ID: ca2092a1-c273-4878-9b4b-0d60115bf5ea
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community
-- Date: 2018-09-03
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((((CommandLine ILIKE '% JAB%' OR CommandLine ILIKE '% SUVYI%' OR CommandLine ILIKE '% SQBFAFgA%' OR CommandLine ILIKE '% aQBlAHgA%' OR CommandLine ILIKE '% aWV4I%' OR CommandLine ILIKE '% IAA%' OR CommandLine ILIKE '% IAB%' OR CommandLine ILIKE '% UwB%' OR CommandLine ILIKE '% cwB%')) AND (CommandLine ILIKE '% -e%')) OR ((CommandLine ILIKE '%.exe -ENCOD %' OR CommandLine ILIKE '% BA^J e-%'))) AND NOT ((CommandLine ILIKE '% -ExecutionPolicy remotesigned %')))
