-- Title: Shell Invocation Via Ssh - Linux
-- ID: 8737b7f6-8df3-4bb7-b1da-06019b99b687
-- Status: test
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date: 2024-08-29
-- Tags: attack.execution, attack.t1059
-- Description: Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/bin/bash%' OR CommandLine LIKE '%/bin/dash%' OR CommandLine LIKE '%/bin/fish%' OR CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%/bin/zsh%' OR CommandLine LIKE '%sh 0<&2 1>&2%' OR CommandLine LIKE '%sh 1>&2 0<&2%')) AND (Image="*/ssh" AND (CommandLine LIKE '%ProxyCommand=;%' OR CommandLine LIKE '%permitlocalcommand=yes%' OR CommandLine LIKE '%localhost%')))
