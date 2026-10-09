-- Title: HackTool - SharPersist Execution
-- ID: 26488ad0-f9fd-4536-876f-52fea846a2e4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-15
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053
-- Description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -t schtask -c %' OR CommandLine LIKE '% -t startupfolder -c %')) OR ((CommandLine LIKE '% -t reg -c %' AND CommandLine LIKE '% -m add%')) OR ((CommandLine LIKE '% -t service -c %' AND CommandLine LIKE '% -m add%')) OR ((CommandLine LIKE '% -t schtask -c %' AND CommandLine LIKE '% -m add%')) OR ((Image="*\\SharPersist.exe") OR (Product = 'SharPersist')))
