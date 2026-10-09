-- Title: Security Tools Keyword Lookup Via Findstr.EXE
-- ID: 4fe074b4-b833-4081-8f24-7dcfeca72b42
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2023-10-20
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects execution of "findstr" to search for common names of security tools. Attackers often pipe the results of recon commands such as "tasklist" or "whoami" to "findstr" in order to filter out the results.
-- This detection focuses on the keywords that the attacker might use as a filter.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% avira' OR CommandLine ILIKE '% avira\"' OR CommandLine ILIKE '% cb' OR CommandLine ILIKE '% cb\"' OR CommandLine ILIKE '% cylance' OR CommandLine ILIKE '% cylance\"' OR CommandLine ILIKE '% defender' OR CommandLine ILIKE '% defender\"' OR CommandLine ILIKE '% kaspersky' OR CommandLine ILIKE '% kaspersky\"' OR CommandLine ILIKE '% kes' OR CommandLine ILIKE '% kes\"' OR CommandLine ILIKE '% mc' OR CommandLine ILIKE '% mc\"' OR CommandLine ILIKE '% sec' OR CommandLine ILIKE '% sec\"' OR CommandLine ILIKE '% sentinel' OR CommandLine ILIKE '% sentinel\"' OR CommandLine ILIKE '% symantec' OR CommandLine ILIKE '% symantec\"' OR CommandLine ILIKE '% virus' OR CommandLine ILIKE '% virus\"')) AND (((Image ILIKE '%\\find.exe' OR Image ILIKE '%\\findstr.exe')) OR ((OriginalFileName = 'FIND.EXE' OR OriginalFileName = 'FINDSTR.EXE'))))
