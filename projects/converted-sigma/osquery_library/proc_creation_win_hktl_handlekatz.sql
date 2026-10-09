-- Title: HackTool - HandleKatz LSASS Dumper Execution
-- ID: ca621ba5-54ab-4035-9942-d378e6fcde3c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-18
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%--pid:%' AND CommandLine LIKE '%--outfile:%') AND (CommandLine LIKE '%.dmp%' OR CommandLine LIKE '%lsass%' OR CommandLine LIKE '%.obf%' OR CommandLine LIKE '%dump%')) OR (Image="*\\loader.exe" AND CommandLine LIKE '%--pid:%') OR ((Hashes LIKE '%IMPHASH=38D9E015591BBFD4929E0D0F47FA0055%' OR Hashes LIKE '%IMPHASH=0E2216679CA6E1094D63322E3412D650%')))
