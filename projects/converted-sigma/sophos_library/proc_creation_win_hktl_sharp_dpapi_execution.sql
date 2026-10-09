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

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\SharpDPAPI.exe') OR (OriginalFileName = 'SharpDPAPI.exe')) OR (((CommandLine ILIKE '% backupkey %' OR CommandLine ILIKE '% blob %' OR CommandLine ILIKE '% certificates %' OR CommandLine ILIKE '% credentials %' OR CommandLine ILIKE '% keepass %' OR CommandLine ILIKE '% masterkeys %' OR CommandLine ILIKE '% rdg %' OR CommandLine ILIKE '% vaults %')) AND (((CommandLine ILIKE '% /file:%' OR CommandLine ILIKE '% /machine%' OR CommandLine ILIKE '% /mkfile:%' OR CommandLine ILIKE '% /password:%' OR CommandLine ILIKE '% /pvk:%' OR CommandLine ILIKE '% /server:%' OR CommandLine ILIKE '% /target:%' OR CommandLine ILIKE '% /unprotect%')) OR ((CommandLine ILIKE '% {%' AND CommandLine ILIKE '%}:%')))))
