-- Title: Suspicious PowerShell IEX Execution Patterns
-- ID: 09576804-7a05-458e-a817-eb718ca91f54
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-03-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious ways to run Invoke-Execution using IEX alias
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '% | iex;%' OR CommandLine LIKE '% | iex %' OR CommandLine LIKE '% | iex}%' OR CommandLine LIKE '% | IEX ;%' OR CommandLine LIKE '% | IEX -Error%' OR CommandLine LIKE '% | IEX (new%' OR CommandLine LIKE '%);IEX %')) AND ((CommandLine LIKE '%::FromBase64String%' OR CommandLine LIKE '%.GetString([System.Convert]::%'))) OR ((CommandLine LIKE '%)|iex;$%' OR CommandLine LIKE '%);iex($%' OR CommandLine LIKE '%);iex $%' OR CommandLine LIKE '% | IEX | %' OR CommandLine LIKE '% | iex\\\"%')))
