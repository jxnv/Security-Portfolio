-- Title: Suspicious Download From Direct IP Via Bitsadmin
-- ID: 99c840f2-2012-46fd-9141-c761987550ef
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003
-- Description: Detects usage of bitsadmin downloading a file using an URL that contains an IP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%://1%' OR CommandLine LIKE '%://2%' OR CommandLine LIKE '%://3%' OR CommandLine LIKE '%://4%' OR CommandLine LIKE '%://5%' OR CommandLine LIKE '%://6%' OR CommandLine LIKE '%://7%' OR CommandLine LIKE '%://8%' OR CommandLine LIKE '%://9%')) AND ((CommandLine LIKE '% /transfer %' OR CommandLine LIKE '% /create %' OR CommandLine LIKE '% /addfile %')) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName = 'bitsadmin.exe'))) AND NOT ((CommandLine LIKE '%://7-%')))
