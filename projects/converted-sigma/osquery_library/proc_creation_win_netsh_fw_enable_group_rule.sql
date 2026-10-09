-- Title: Netsh Allow Group Policy on Microsoft Defender Firewall
-- ID: 347906f3-e207-4d18-ae5b-a9403d6bcdef
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-09
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Adversaries may modify system firewalls in order to bypass controls limiting network usage
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%advfirewall%' AND CommandLine LIKE '%firewall%' AND CommandLine LIKE '%set%' AND CommandLine LIKE '%rule%' AND CommandLine LIKE '%group=%' AND CommandLine LIKE '%new%' AND CommandLine LIKE '%enable=Yes%')) AND ((Image="*\\netsh.exe") OR (OriginalFileName = 'netsh.exe')))
