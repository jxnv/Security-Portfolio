-- Title: HackTool - Covenant PowerShell Launcher
-- ID: c260b6db-48ba-4b4a-a76f-2f67644e99d2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2020-06-04
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1564.003
-- Description: Detects suspicious command lines used in Covenant luanchers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%-Sta%' AND CommandLine LIKE '%-Nop%' AND CommandLine LIKE '%-Window%' AND CommandLine LIKE '%Hidden%') AND (CommandLine LIKE '%-Command%' OR CommandLine LIKE '%-EncodedCommand%')) OR ((CommandLine LIKE '%sv o (New-Object IO.MemorySteam);sv d %' OR CommandLine LIKE '%mshta file.hta%' OR CommandLine LIKE '%GruntHTTP%' OR CommandLine LIKE '%-EncodedCommand cwB2ACAAbwAgA%')))
