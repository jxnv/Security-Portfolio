-- Title: HackTool - HandleKatz LSASS Dumper Execution
-- ID: ca621ba5-54ab-4035-9942-d378e6fcde3c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-18
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%--pid:%' AND CommandLine ILIKE '%--outfile:%') AND (CommandLine ILIKE '%.dmp%' OR CommandLine ILIKE '%lsass%' OR CommandLine ILIKE '%.obf%' OR CommandLine ILIKE '%dump%')) OR (Image ILIKE '%\\loader.exe' AND CommandLine ILIKE '%--pid:%') OR ((Hashes ILIKE '%IMPHASH=38D9E015591BBFD4929E0D0F47FA0055%' OR Hashes ILIKE '%IMPHASH=0E2216679CA6E1094D63322E3412D650%')))
