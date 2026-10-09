-- Title: HackTool - CrackMapExec PowerShell Obfuscation
-- ID: 6f8b3439-a203-45dc-a88b-abf57ea15ccf
-- Status: test
-- Level: high
-- Author: Thomas Patzke
-- Date: 2020-05-22
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027.005
-- Description: The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%join*split%' OR CommandLine ILIKE '%( $ShellId[1]+$ShellId[13]+'x')%' OR CommandLine ILIKE '%( $PSHome[*]+$PSHOME[*]+%' OR CommandLine ILIKE '%( $env:Public[13]+$env:Public[5]+'x')%' OR CommandLine ILIKE '%( $env:ComSpec[4,*,25]-Join'')%' OR CommandLine ILIKE '%[1,3]+'x'-Join'')%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
