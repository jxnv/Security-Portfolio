-- Title: PsExec/PAExec Escalation to LOCAL SYSTEM
-- ID: 8834e2f7-6b4b-4f09-8906-d2276470ee23
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-11-23
-- Tags: attack.resource-development, attack.t1587.001
-- Description: Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%psexec%' OR CommandLine LIKE '%paexec%' OR CommandLine LIKE '%accepteula%')) AND ((CommandLine LIKE '% -s cmd%' OR CommandLine LIKE '% -s -i cmd%' OR CommandLine LIKE '% -i -s cmd%' OR CommandLine LIKE '% -s pwsh%' OR CommandLine LIKE '% -s -i pwsh%' OR CommandLine LIKE '% -i -s pwsh%' OR CommandLine LIKE '% -s powershell%' OR CommandLine LIKE '% -s -i powershell%' OR CommandLine LIKE '% -i -s powershell%')))
