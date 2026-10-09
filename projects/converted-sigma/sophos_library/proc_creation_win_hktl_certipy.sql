-- Title: HackTool - Certipy Execution
-- ID: 6938366d-8954-4ddc-baff-c830b3ba8fcd
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), Sittikorn Sangrattanapitak
-- Date: 2023-04-17
-- Tags: attack.discovery, attack.credential-access, attack.t1649
-- Description: Detects Certipy execution, a tool for Active Directory Certificate Services enumeration and abuse based on PE metadata characteristics and common command line arguments.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\Certipy.exe') OR (OriginalFileName = 'Certipy.exe') OR (Description ILIKE '%Certipy%')) OR (((CommandLine ILIKE '% account %' OR CommandLine ILIKE '% auth %' OR CommandLine ILIKE '% cert %' OR CommandLine ILIKE '% find %' OR CommandLine ILIKE '% forge %' OR CommandLine ILIKE '% ptt %' OR CommandLine ILIKE '% relay %' OR CommandLine ILIKE '% req %' OR CommandLine ILIKE '% shadow %' OR CommandLine ILIKE '% template %')) AND ((CommandLine ILIKE '% -bloodhound%' OR CommandLine ILIKE '% -ca-pfx %' OR CommandLine ILIKE '% -dc-ip %' OR CommandLine ILIKE '% -kirbi%' OR CommandLine ILIKE '% -old-bloodhound%' OR CommandLine ILIKE '% -pfx %' OR CommandLine ILIKE '% -target%' OR CommandLine ILIKE '% -template%' OR CommandLine ILIKE '% -username %' OR CommandLine ILIKE '% -vulnerable%' OR CommandLine ILIKE '%auth -pfx%' OR CommandLine ILIKE '%shadow auto%' OR CommandLine ILIKE '%shadow list%'))))
