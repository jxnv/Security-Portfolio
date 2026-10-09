-- Title: Potential Privilege Escalation To LOCAL SYSTEM
-- ID: 207b0396-3689-42d9-8399-4222658efc99
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-05-22
-- Tags: attack.resource-development, attack.t1587.001
-- Description: Detects unknown program using commandline flags usually used by tools such as PsExec and PAExec to start programs with SYSTEM Privileges
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -s cmd%' OR CommandLine LIKE '% -s -i cmd%' OR CommandLine LIKE '% -i -s cmd%' OR CommandLine LIKE '% -s pwsh%' OR CommandLine LIKE '% -s -i pwsh%' OR CommandLine LIKE '% -i -s pwsh%' OR CommandLine LIKE '% -s powershell%' OR CommandLine LIKE '% -s -i powershell%' OR CommandLine LIKE '% -i -s powershell%')) AND NOT (((CommandLine LIKE '%paexec%' OR CommandLine LIKE '%PsExec%' OR CommandLine LIKE '%accepteula%'))))
