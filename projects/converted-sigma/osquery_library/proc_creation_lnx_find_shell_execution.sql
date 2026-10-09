-- Title: Shell Execution via Find - Linux
-- ID: 6adfbf8f-52be-4444-9bac-81b539624146
-- Status: test
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date: 2024-09-02
-- Tags: attack.discovery, attack.t1083
-- Description: Detects the use of the find command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or exploitation attempt.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/bin/bash%' OR CommandLine LIKE '%/bin/dash%' OR CommandLine LIKE '%/bin/fish%' OR CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%/bin/zsh%')) AND (Image="*/find" AND (CommandLine LIKE '% . %' AND CommandLine LIKE '%-exec%')))
