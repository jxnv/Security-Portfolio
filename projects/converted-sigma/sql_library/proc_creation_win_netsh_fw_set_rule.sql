-- Title: Firewall Rule Update Via Netsh.EXE
-- ID: a70dcb37-3bee-453a-99df-d0c683151be6
-- Status: test
-- Level: medium
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-07-18
-- Tags: attack.defense-impairment
-- Description: Detects execution of netsh with the "advfirewall" and the "set" option in order to set new values for properties of a existing rule
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% firewall %' AND CommandLine ILIKE '% set %')) AND ((Image ILIKE '%\\netsh.exe') OR (OriginalFileName = 'netsh.exe')))
