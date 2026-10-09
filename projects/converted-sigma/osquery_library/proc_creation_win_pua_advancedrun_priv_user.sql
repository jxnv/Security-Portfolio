-- Title: PUA - AdvancedRun Suspicious Execution
-- ID: fa00b701-44c6-4679-994d-5a18afa8a707
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-20
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.002
-- Description: Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/EXEFilename%' OR CommandLine LIKE '%/CommandLine%')) AND (((CommandLine LIKE '% /RunAs 8 %' OR CommandLine LIKE '% /RunAs 4 %' OR CommandLine LIKE '% /RunAs 10 %' OR CommandLine LIKE '% /RunAs 11 %')) OR ((CommandLine="*/RunAs 8" OR CommandLine="*/RunAs 4" OR CommandLine="*/RunAs 10" OR CommandLine="*/RunAs 11"))))
