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

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%cmd.exe/c%' OR CommandLine ILIKE '%\\cmd/c%' OR CommandLine ILIKE '%\"cmd/c%' OR CommandLine ILIKE '%cmd.exe/k%' OR CommandLine ILIKE '%\\cmd/k%' OR CommandLine ILIKE '%\"cmd/k%' OR CommandLine ILIKE '%cmd.exe/r%' OR CommandLine ILIKE '%\\cmd/r%' OR CommandLine ILIKE '%\"cmd/r%')) OR ((CommandLine ILIKE '%/cwhoami%' OR CommandLine ILIKE '%/cpowershell%' OR CommandLine ILIKE '%/cschtasks%' OR CommandLine ILIKE '%/cbitsadmin%' OR CommandLine ILIKE '%/ccertutil%' OR CommandLine ILIKE '%/kwhoami%' OR CommandLine ILIKE '%/kpowershell%' OR CommandLine ILIKE '%/kschtasks%' OR CommandLine ILIKE '%/kbitsadmin%' OR CommandLine ILIKE '%/kcertutil%')) OR ((CommandLine ILIKE '%cmd.exe /c%' OR CommandLine ILIKE '%cmd /c%' OR CommandLine ILIKE '%cmd.exe /k%' OR CommandLine ILIKE '%cmd /k%' OR CommandLine ILIKE '%cmd.exe /r%' OR CommandLine ILIKE '%cmd /r%'))) AND NOT ((((CommandLine ILIKE '%AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\node_modules%') OR (CommandLine ILIKE '%cmd.exe/c .') OR (CommandLine = 'cmd.exe /c') OR (CommandLine = 'cmd /c')) OR ((CommandLine ILIKE '%cmd.exe /c %' OR CommandLine ILIKE '%cmd /c %' OR CommandLine ILIKE '%cmd.exe /k %' OR CommandLine ILIKE '%cmd /k %' OR CommandLine ILIKE '%cmd.exe /r %' OR CommandLine ILIKE '%cmd /r %')))))
