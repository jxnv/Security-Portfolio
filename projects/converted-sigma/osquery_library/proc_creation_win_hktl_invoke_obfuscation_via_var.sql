-- Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
-- ID: e9f55347-2928-4c06-88e5-1a7f8169942e
-- Status: test
-- Level: high
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-13
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%&&set%' AND CommandLine LIKE '%cmd%' AND CommandLine LIKE '%/c%' AND CommandLine LIKE '%-f%') AND (CommandLine LIKE '%{0}%' OR CommandLine LIKE '%{1}%' OR CommandLine LIKE '%{2}%' OR CommandLine LIKE '%{3}%' OR CommandLine LIKE '%{4}%' OR CommandLine LIKE '%{5}%'))
