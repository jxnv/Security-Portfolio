-- Title: Suspicious RunAs-Like Flag Combination
-- ID: 50d66fb0-03f8-4da0-8add-84e77d12a020
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-11-11
-- Tags: attack.privilege-escalation
-- Description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -c cmd%' OR CommandLine LIKE '% -c \"cmd%' OR CommandLine LIKE '% -c powershell%' OR CommandLine LIKE '% -c \"powershell%' OR CommandLine LIKE '% --command cmd%' OR CommandLine LIKE '% --command powershell%' OR CommandLine LIKE '% -c whoami%' OR CommandLine LIKE '% -c wscript%' OR CommandLine LIKE '% -c cscript%')) AND ((CommandLine LIKE '% -u system %' OR CommandLine LIKE '% --user system %' OR CommandLine LIKE '% -u NT%' OR CommandLine LIKE '% -u \"NT%' OR CommandLine LIKE '% -u 'NT%' OR CommandLine LIKE '% --system %' OR CommandLine LIKE '% -u administrator %')))
