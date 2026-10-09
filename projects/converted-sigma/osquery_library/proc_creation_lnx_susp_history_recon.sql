-- Title: Print History File Contents
-- ID: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.reconnaissance, attack.t1592.004
-- Description: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*/cat" OR Image="*/head" OR Image="*/tail" OR Image="*/more")) AND (((CommandLine LIKE '%/.bash_history%' OR CommandLine LIKE '%/.zsh_history%')) OR ((CommandLine="*_history" OR CommandLine="*.history" OR CommandLine="*zhistory"))))
