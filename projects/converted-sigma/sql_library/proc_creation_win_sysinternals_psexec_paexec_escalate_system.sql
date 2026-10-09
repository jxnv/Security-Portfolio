-- Title: PsExec/PAExec Escalation to LOCAL SYSTEM
-- ID: 8834e2f7-6b4b-4f09-8906-d2276470ee23
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-11-23
-- Tags: attack.resource-development, attack.t1587.001
-- Description: Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%psexec%' OR CommandLine ILIKE '%paexec%' OR CommandLine ILIKE '%accepteula%')) AND ((CommandLine ILIKE '% -s cmd%' OR CommandLine ILIKE '% -s -i cmd%' OR CommandLine ILIKE '% -i -s cmd%' OR CommandLine ILIKE '% -s pwsh%' OR CommandLine ILIKE '% -s -i pwsh%' OR CommandLine ILIKE '% -i -s pwsh%' OR CommandLine ILIKE '% -s powershell%' OR CommandLine ILIKE '% -s -i powershell%' OR CommandLine ILIKE '% -i -s powershell%')))
