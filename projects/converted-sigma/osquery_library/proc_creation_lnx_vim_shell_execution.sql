-- Title: Vim GTFOBin Abuse - Linux
-- ID: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
-- Date: 2022-12-28
-- Tags: attack.execution, attack.discovery, attack.t1059, attack.t1083
-- Description: Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
-- Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%:!/%' OR CommandLine LIKE '%:!$%' OR CommandLine LIKE '%:!..%' OR CommandLine LIKE '%:lua %' OR CommandLine LIKE '%:py %' OR CommandLine LIKE '%:shell%' OR CommandLine LIKE '%/bin/bash%' OR CommandLine LIKE '%/bin/dash%' OR CommandLine LIKE '%/bin/fish%' OR CommandLine LIKE '%/bin/sh%' OR CommandLine LIKE '%/bin/csh%' OR CommandLine LIKE '%/bin/ksh%' OR CommandLine LIKE '%/bin/zsh%' OR CommandLine LIKE '%/bin/tmux%')) AND ((Image="*/rvim" OR Image="*/vi" OR Image="*/vim" OR Image="*/vimdiff") AND (CommandLine LIKE '% --cmd %' OR CommandLine LIKE '% -c%')))
