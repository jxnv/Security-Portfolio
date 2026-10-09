-- Title: Shell Execution via Rsync - Linux
-- ID: e2326866-609f-4015-aea9-7ec634e8aa04
-- Status: experimental
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
-- Date: 2024-09-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/ash %' OR CommandLine LIKE '%/bash %' OR CommandLine LIKE '%/dash %' OR CommandLine LIKE '%/csh %' OR CommandLine LIKE '%/sh %' OR CommandLine LIKE '%/zsh %' OR CommandLine LIKE '%/tcsh %' OR CommandLine LIKE '%/ksh %' OR CommandLine LIKE '%'ash %' OR CommandLine LIKE '%'bash %' OR CommandLine LIKE '%'dash %' OR CommandLine LIKE '%'csh %' OR CommandLine LIKE '%'sh %' OR CommandLine LIKE '%'zsh %' OR CommandLine LIKE '%'tcsh %' OR CommandLine LIKE '%'ksh %')) AND ((Image="*/rsync" OR Image="*/rsyncd") AND CommandLine LIKE '% -e %'))
