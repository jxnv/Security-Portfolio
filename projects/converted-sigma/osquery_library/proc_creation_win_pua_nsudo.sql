-- Title: PUA - NSudo Execution
-- ID: 771d1eb5-9587-4568-95fb-9ec44153a012
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali
-- Date: 2022-01-24
-- Tags: attack.execution, attack.t1569.002, attack.s0029
-- Description: Detects the use of NSudo tool for command execution
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-U:S %' OR CommandLine LIKE '%-U:T %' OR CommandLine LIKE '%-U:E %' OR CommandLine LIKE '%-P:E %' OR CommandLine LIKE '%-M:S %' OR CommandLine LIKE '%-M:H %' OR CommandLine LIKE '%-U=S %' OR CommandLine LIKE '%-U=T %' OR CommandLine LIKE '%-U=E %' OR CommandLine LIKE '%-P=E %' OR CommandLine LIKE '%-M=S %' OR CommandLine LIKE '%-M=H %' OR CommandLine LIKE '%-ShowWindowMode:Hide%')) AND (((Image="*\\NSudo.exe" OR Image="*\\NSudoLC.exe" OR Image="*\\NSudoLG.exe")) OR ((OriginalFileName = 'NSudo.exe' OR OriginalFileName = 'NSudoLC.exe' OR OriginalFileName = 'NSudoLG.exe'))))
