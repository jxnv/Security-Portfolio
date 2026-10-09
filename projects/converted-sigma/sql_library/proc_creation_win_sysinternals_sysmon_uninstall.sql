-- Title: Uninstall Sysinternals Sysmon
-- ID: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-01-12
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-u%' OR CommandLine ILIKE '%/u%')) AND (((Image ILIKE '%\\Sysmon64.exe' OR Image ILIKE '%\\Sysmon64a.exe' OR Image ILIKE '%\\Sysmon.exe')) OR (Description = 'System activity monitor')))
