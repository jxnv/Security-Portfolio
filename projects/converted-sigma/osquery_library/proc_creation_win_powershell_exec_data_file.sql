-- Title: Powershell Inline Execution From A File
-- ID: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-12-25
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects inline execution of PowerShell code from a file
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%iex %' OR CommandLine LIKE '%Invoke-Expression %' OR CommandLine LIKE '%Invoke-Command %' OR CommandLine LIKE '%icm %')) AND (CommandLine LIKE '% -raw%') AND ((CommandLine LIKE '%cat %' OR CommandLine LIKE '%get-content %' OR CommandLine LIKE '%type %')))
