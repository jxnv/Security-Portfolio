-- Title: HackTool - SharpDPAPI Execution
-- ID: c7d33b50-f690-4b51-8cfb-0fb912a31e57
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-06-26
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.003
-- Description: Detects the execution of the SharpDPAPI tool based on CommandLine flags and PE metadata.
-- SharpDPAPI is a C# port of some DPAPI functionality from the Mimikatz project.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\SharpDPAPI.exe") OR (OriginalFileName = 'SharpDPAPI.exe')) OR (((CommandLine LIKE '% backupkey %' OR CommandLine LIKE '% blob %' OR CommandLine LIKE '% certificates %' OR CommandLine LIKE '% credentials %' OR CommandLine LIKE '% keepass %' OR CommandLine LIKE '% masterkeys %' OR CommandLine LIKE '% rdg %' OR CommandLine LIKE '% vaults %')) AND (((CommandLine LIKE '% /file:%' OR CommandLine LIKE '% /machine%' OR CommandLine LIKE '% /mkfile:%' OR CommandLine LIKE '% /password:%' OR CommandLine LIKE '% /pvk:%' OR CommandLine LIKE '% /server:%' OR CommandLine LIKE '% /target:%' OR CommandLine LIKE '% /unprotect%')) OR ((CommandLine LIKE '% {%' AND CommandLine LIKE '%}:%')))))
