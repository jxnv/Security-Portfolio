-- Title: HackTool - Covenant PowerShell Launcher
-- ID: c260b6db-48ba-4b4a-a76f-2f67644e99d2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2020-06-04
-- Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1564.003
-- Description: Detects suspicious command lines used in Covenant luanchers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-Sta%' AND CommandLine ILIKE '%-Nop%' AND CommandLine ILIKE '%-Window%' AND CommandLine ILIKE '%Hidden%') AND (CommandLine ILIKE '%-Command%' OR CommandLine ILIKE '%-EncodedCommand%')) OR ((CommandLine ILIKE '%sv o (New-Object IO.MemorySteam);sv d %' OR CommandLine ILIKE '%mshta file.hta%' OR CommandLine ILIKE '%GruntHTTP%' OR CommandLine ILIKE '%-EncodedCommand cwB2ACAAbwAgA%')))
