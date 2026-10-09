-- Title: Automated Collection Command Prompt
-- ID: f576a613-2392-4067-9d1a-9345fb58d8d1
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-28
-- Tags: attack.collection, attack.t1119, attack.credential-access, attack.t1552.001
-- Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.doc%' OR CommandLine ILIKE '%.docx%' OR CommandLine ILIKE '%.xls%' OR CommandLine ILIKE '%.xlsx%' OR CommandLine ILIKE '%.ppt%' OR CommandLine ILIKE '%.pptx%' OR CommandLine ILIKE '%.rtf%' OR CommandLine ILIKE '%.pdf%' OR CommandLine ILIKE '%.txt%')) AND (((CommandLine ILIKE '%dir %' AND CommandLine ILIKE '% /b %' AND CommandLine ILIKE '% /s %')) OR (OriginalFileName = 'FINDSTR.EXE' AND (CommandLine ILIKE '% /e %' OR CommandLine ILIKE '% /si %'))))
