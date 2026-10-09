-- Title: Rundll32 UNC Path Execution
-- ID: 5cdb711b-5740-4fb2-ba88-f7945027afac
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-10
-- Tags: attack.execution, attack.lateral-movement, attack.stealth, attack.t1021.002, attack.t1218.011
-- Description: Detects rundll32 execution where the DLL is located on a remote location (share).
-- Threat actors can abuse the rundll32.exe binary to execute remote DLLs from a UNC pathh.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '% \\\\\\\\%' OR CommandLine LIKE '% '\\\\\\\\%' OR CommandLine LIKE '% \"\\\\\\\\%')) AND ((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.EXE') OR (CommandLine LIKE '%rundll32%'))) AND NOT ((CommandLine LIKE '%\\\\\\\\.\\\\pipe%')))
