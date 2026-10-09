-- Title: PUA - NirCmd Execution
-- ID: 4e2ed651-1906-4a59-a78a-18220fca1b22
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-24
-- Tags: attack.execution, attack.t1569.002, attack.s0029
-- Description: Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '% execmd %' OR CommandLine ILIKE '%.exe script %' OR CommandLine ILIKE '%.exe shexec %' OR CommandLine ILIKE '% runinteractive %')) OR ((Image ILIKE '%\\NirCmd.exe') OR (OriginalFileName = 'NirCmd.exe'))) OR (((CommandLine ILIKE '% exec %' OR CommandLine ILIKE '% exec2 %')) AND ((CommandLine ILIKE '% show %' OR CommandLine ILIKE '% hide %'))))
