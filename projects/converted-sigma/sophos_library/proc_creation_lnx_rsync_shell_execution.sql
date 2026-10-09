-- Title: Shell Execution via Rsync - Linux
-- ID: e2326866-609f-4015-aea9-7ec634e8aa04
-- Status: experimental
-- Level: high
-- Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
-- Date: 2024-09-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%/ash %' OR CommandLine ILIKE '%/bash %' OR CommandLine ILIKE '%/dash %' OR CommandLine ILIKE '%/csh %' OR CommandLine ILIKE '%/sh %' OR CommandLine ILIKE '%/zsh %' OR CommandLine ILIKE '%/tcsh %' OR CommandLine ILIKE '%/ksh %' OR CommandLine ILIKE '%'ash %' OR CommandLine ILIKE '%'bash %' OR CommandLine ILIKE '%'dash %' OR CommandLine ILIKE '%'csh %' OR CommandLine ILIKE '%'sh %' OR CommandLine ILIKE '%'zsh %' OR CommandLine ILIKE '%'tcsh %' OR CommandLine ILIKE '%'ksh %')) AND ((Image ILIKE '%/rsync' OR Image ILIKE '%/rsyncd') AND CommandLine ILIKE '% -e %'))
