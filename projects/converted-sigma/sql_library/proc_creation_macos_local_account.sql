-- Title: Local System Accounts Discovery - MacOs
-- ID: ddf36b67-e872-4507-ab2e-46bda21b842c
-- Status: test
-- Level: low
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-08
-- Tags: attack.discovery, attack.t1087.001
-- Description: Detects enumeration of local system accounts on MacOS systems.
-- This can be used by attackers to identify accounts for lateral movement or privilege escalation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/dscacheutil' AND (CommandLine ILIKE '%-q%' AND CommandLine ILIKE '%user%')) OR (Image ILIKE '%/dscl' AND (CommandLine ILIKE '%list%' AND CommandLine ILIKE '%/users%')) OR (Image ILIKE '%/ls' AND (CommandLine ILIKE '%/Users' OR CommandLine ILIKE '%/Users'' OR CommandLine ILIKE '%/Users\"')) OR (Image ILIKE '%/id') OR ((Image ILIKE '%/who' OR Image ILIKE '%/w' OR Image ILIKE '%/users' OR Image ILIKE '%/last')) OR ((Image ILIKE '%/defaults' OR Image ILIKE '%/plutil') AND CommandLine ILIKE '%com.apple.loginwindow%') OR (Image ILIKE '%/lsof' AND CommandLine ILIKE '%-u%') OR ((Image ILIKE '%/cat' OR Image ILIKE '%/awk' OR Image ILIKE '%/grep') AND (CommandLine ILIKE '%/etc/passwd%' OR CommandLine ILIKE '%/etc/sudoers%')) OR (CommandLine ILIKE '%'*:0:'%'))
