-- Title: Suspicious RunAs-Like Flag Combination
-- ID: 50d66fb0-03f8-4da0-8add-84e77d12a020
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-11-11
-- Tags: attack.privilege-escalation
-- Description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% -c cmd%' OR CommandLine ILIKE '% -c \"cmd%' OR CommandLine ILIKE '% -c powershell%' OR CommandLine ILIKE '% -c \"powershell%' OR CommandLine ILIKE '% --command cmd%' OR CommandLine ILIKE '% --command powershell%' OR CommandLine ILIKE '% -c whoami%' OR CommandLine ILIKE '% -c wscript%' OR CommandLine ILIKE '% -c cscript%')) AND ((CommandLine ILIKE '% -u system %' OR CommandLine ILIKE '% --user system %' OR CommandLine ILIKE '% -u NT%' OR CommandLine ILIKE '% -u \"NT%' OR CommandLine ILIKE '% -u 'NT%' OR CommandLine ILIKE '% --system %' OR CommandLine ILIKE '% -u administrator %')))
