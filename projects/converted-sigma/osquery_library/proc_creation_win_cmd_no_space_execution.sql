-- Title: Cmd.EXE Missing Space Characters Execution Anomaly
-- ID: a16980c2-0c56-4de0-9a79-17971979efdd
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-23
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe.
-- This could be a sign of obfuscation of a fat finger problem (typo by the developer).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%cmd.exe/c%' OR CommandLine LIKE '%\\cmd/c%' OR CommandLine LIKE '%\"cmd/c%' OR CommandLine LIKE '%cmd.exe/k%' OR CommandLine LIKE '%\\cmd/k%' OR CommandLine LIKE '%\"cmd/k%' OR CommandLine LIKE '%cmd.exe/r%' OR CommandLine LIKE '%\\cmd/r%' OR CommandLine LIKE '%\"cmd/r%')) OR ((CommandLine LIKE '%/cwhoami%' OR CommandLine LIKE '%/cpowershell%' OR CommandLine LIKE '%/cschtasks%' OR CommandLine LIKE '%/cbitsadmin%' OR CommandLine LIKE '%/ccertutil%' OR CommandLine LIKE '%/kwhoami%' OR CommandLine LIKE '%/kpowershell%' OR CommandLine LIKE '%/kschtasks%' OR CommandLine LIKE '%/kbitsadmin%' OR CommandLine LIKE '%/kcertutil%')) OR ((CommandLine LIKE '%cmd.exe /c%' OR CommandLine LIKE '%cmd /c%' OR CommandLine LIKE '%cmd.exe /k%' OR CommandLine LIKE '%cmd /k%' OR CommandLine LIKE '%cmd.exe /r%' OR CommandLine LIKE '%cmd /r%'))) AND NOT ((((CommandLine LIKE '%AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules%') OR (CommandLine="*cmd.exe/c .") OR (CommandLine = 'cmd.exe /c') OR (CommandLine = 'cmd /c')) OR ((CommandLine LIKE '%cmd.exe /c %' OR CommandLine LIKE '%cmd /c %' OR CommandLine LIKE '%cmd.exe /k %' OR CommandLine LIKE '%cmd /k %' OR CommandLine LIKE '%cmd.exe /r %' OR CommandLine LIKE '%cmd /r %')))))
