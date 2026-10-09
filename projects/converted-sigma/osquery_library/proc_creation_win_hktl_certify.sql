-- Title: HackTool - Certify Execution
-- ID: 762f2482-ff21-4970-8939-0aa317a886bb
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2023-04-17
-- Tags: attack.discovery, attack.credential-access, attack.t1649
-- Description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\Certify.exe") OR (OriginalFileName = 'Certify.exe') OR (Description LIKE '%Certify%')) OR (((CommandLine LIKE '%.exe cas %' OR CommandLine LIKE '%.exe find %' OR CommandLine LIKE '%.exe pkiobjects %' OR CommandLine LIKE '%.exe request %' OR CommandLine LIKE '%.exe download %')) AND ((CommandLine LIKE '% /vulnerable%' OR CommandLine LIKE '% /template:%' OR CommandLine LIKE '% /altname:%' OR CommandLine LIKE '% /domain:%' OR CommandLine LIKE '% /path:%' OR CommandLine LIKE '% /ca:%'))))
