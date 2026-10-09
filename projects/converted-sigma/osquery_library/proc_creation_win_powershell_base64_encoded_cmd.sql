-- Title: Suspicious Encoded PowerShell Command Line
-- ID: ca2092a1-c273-4878-9b4b-0d60115bf5ea
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, Anton Kutepov, oscd.community
-- Date: 2018-09-03
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((((CommandLine LIKE '% JAB%' OR CommandLine LIKE '% SUVYI%' OR CommandLine LIKE '% SQBFAFgA%' OR CommandLine LIKE '% aQBlAHgA%' OR CommandLine LIKE '% aWV4I%' OR CommandLine LIKE '% IAA%' OR CommandLine LIKE '% IAB%' OR CommandLine LIKE '% UwB%' OR CommandLine LIKE '% cwB%')) AND (CommandLine LIKE '% -e%')) OR ((CommandLine LIKE '%.exe -ENCOD %' OR CommandLine LIKE '% BA^J e-%'))) AND NOT ((CommandLine LIKE '% -ExecutionPolicy remotesigned %')))
