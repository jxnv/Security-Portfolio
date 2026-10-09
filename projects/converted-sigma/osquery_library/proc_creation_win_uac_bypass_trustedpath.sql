-- Title: TrustedPath UAC Bypass Pattern
-- ID: 4ac47ed3-44c2-4b1f-9d51-bf46e8914126
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-08-27
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects indicators of a UAC bypass method by mocking directories
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image LIKE '%C:\\Windows \\System32\\%' OR Image LIKE '%C:\\Windows \\SysWOW64\\%'))
