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

SELECT * FROM processes WHERE ((Image="*/dscacheutil" AND (CommandLine LIKE '%-q%' AND CommandLine LIKE '%user%')) OR (Image="*/dscl" AND (CommandLine LIKE '%list%' AND CommandLine LIKE '%/users%')) OR (Image="*/ls" AND (CommandLine="*/Users" OR CommandLine="*/Users'" OR CommandLine="*/Users\"")) OR (Image="*/id") OR ((Image="*/who" OR Image="*/w" OR Image="*/users" OR Image="*/last")) OR ((Image="*/defaults" OR Image="*/plutil") AND CommandLine LIKE '%com.apple.loginwindow%') OR (Image="*/lsof" AND CommandLine LIKE '%-u%') OR ((Image="*/cat" OR Image="*/awk" OR Image="*/grep") AND (CommandLine LIKE '%/etc/passwd%' OR CommandLine LIKE '%/etc/sudoers%')) OR (CommandLine LIKE '%'*:0:'%'))
