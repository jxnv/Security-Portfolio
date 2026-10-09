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

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%:!/%' OR CommandLine ILIKE '%:!$%' OR CommandLine ILIKE '%:!..%' OR CommandLine ILIKE '%:lua %' OR CommandLine ILIKE '%:py %' OR CommandLine ILIKE '%:shell%' OR CommandLine ILIKE '%/bin/bash%' OR CommandLine ILIKE '%/bin/dash%' OR CommandLine ILIKE '%/bin/fish%' OR CommandLine ILIKE '%/bin/sh%' OR CommandLine ILIKE '%/bin/csh%' OR CommandLine ILIKE '%/bin/ksh%' OR CommandLine ILIKE '%/bin/zsh%' OR CommandLine ILIKE '%/bin/tmux%')) AND ((Image ILIKE '%/rvim' OR Image ILIKE '%/vi' OR Image ILIKE '%/vim' OR Image ILIKE '%/vimdiff') AND (CommandLine ILIKE '% --cmd %' OR CommandLine ILIKE '% -c%')))
