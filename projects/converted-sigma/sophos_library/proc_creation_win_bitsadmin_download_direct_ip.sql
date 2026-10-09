-- Title: Suspicious Download From Direct IP Via Bitsadmin
-- ID: 99c840f2-2012-46fd-9141-c761987550ef
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003
-- Description: Detects usage of bitsadmin downloading a file using an URL that contains an IP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%://1%' OR CommandLine ILIKE '%://2%' OR CommandLine ILIKE '%://3%' OR CommandLine ILIKE '%://4%' OR CommandLine ILIKE '%://5%' OR CommandLine ILIKE '%://6%' OR CommandLine ILIKE '%://7%' OR CommandLine ILIKE '%://8%' OR CommandLine ILIKE '%://9%')) AND ((CommandLine ILIKE '% /transfer %' OR CommandLine ILIKE '% /create %' OR CommandLine ILIKE '% /addfile %')) AND ((Image ILIKE '%\\bitsadmin.exe') OR (OriginalFileName = 'bitsadmin.exe'))) AND NOT ((CommandLine ILIKE '%://7-%')))
