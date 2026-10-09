-- Title: Imports Registry Key From a File
-- ID: 73bba97f-a82d-42ce-b315-9182e76c57b1
-- Status: test
-- Level: medium
-- Author: Oddvar Moe, Sander Wiebing, oscd.community
-- Date: 2020-10-07
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects the import of the specified file to the registry with regedit.exe.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '% /i %' OR CommandLine ILIKE '% /s %' OR CommandLine ILIKE '%.reg%')) AND ((Image ILIKE '%\\regedit.exe') OR (OriginalFileName = 'REGEDIT.EXE'))) AND NOT ((((CommandLine ILIKE '% -e %' OR CommandLine ILIKE '% -a %' OR CommandLine ILIKE '% -c %')) AND (REGEXP_LIKE(CommandLine, ':[^ \\]')))))
