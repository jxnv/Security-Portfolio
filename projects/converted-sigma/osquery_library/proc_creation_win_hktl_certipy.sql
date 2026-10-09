-- Title: HackTool - Certipy Execution
-- ID: 6938366d-8954-4ddc-baff-c830b3ba8fcd
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), Sittikorn Sangrattanapitak
-- Date: 2023-04-17
-- Tags: attack.discovery, attack.credential-access, attack.t1649
-- Description: Detects Certipy execution, a tool for Active Directory Certificate Services enumeration and abuse based on PE metadata characteristics and common command line arguments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\Certipy.exe") OR (OriginalFileName = 'Certipy.exe') OR (Description LIKE '%Certipy%')) OR (((CommandLine LIKE '% account %' OR CommandLine LIKE '% auth %' OR CommandLine LIKE '% cert %' OR CommandLine LIKE '% find %' OR CommandLine LIKE '% forge %' OR CommandLine LIKE '% ptt %' OR CommandLine LIKE '% relay %' OR CommandLine LIKE '% req %' OR CommandLine LIKE '% shadow %' OR CommandLine LIKE '% template %')) AND ((CommandLine LIKE '% -bloodhound%' OR CommandLine LIKE '% -ca-pfx %' OR CommandLine LIKE '% -dc-ip %' OR CommandLine LIKE '% -kirbi%' OR CommandLine LIKE '% -old-bloodhound%' OR CommandLine LIKE '% -pfx %' OR CommandLine LIKE '% -target%' OR CommandLine LIKE '% -template%' OR CommandLine LIKE '% -username %' OR CommandLine LIKE '% -vulnerable%' OR CommandLine LIKE '%auth -pfx%' OR CommandLine LIKE '%shadow auto%' OR CommandLine LIKE '%shadow list%'))))
