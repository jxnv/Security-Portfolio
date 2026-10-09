-- Title: Firewall Disabled via Netsh.EXE
-- ID: 57c4bf16-227f-4394-8ec7-1b745ee061c3
-- Status: test
-- Level: medium
-- Author: Fatih Sirin
-- Date: 2019-11-01
-- Tags: attack.defense-impairment, attack.t1686.003, attack.s0108
-- Description: Detects netsh commands that turns off the Windows firewall
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\netsh.exe") OR (OriginalFileName = 'netsh.exe')) AND (((CommandLine LIKE '%firewall%' AND CommandLine LIKE '%set%' AND CommandLine LIKE '%opmode%' AND CommandLine LIKE '%disable%')) OR ((CommandLine LIKE '%advfirewall%' AND CommandLine LIKE '%set%' AND CommandLine LIKE '%state%' AND CommandLine LIKE '%off%'))))
