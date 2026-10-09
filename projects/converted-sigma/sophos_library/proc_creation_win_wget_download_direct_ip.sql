-- Title: Suspicious File Download From IP Via Wget.EXE
-- ID: 17f0c0a8-8bd5-4ee0-8c5f-a342c0199f35
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-27
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads directly from IP addresses using Wget.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%.ps1' OR CommandLine ILIKE '%.ps1'' OR CommandLine ILIKE '%.ps1\"' OR CommandLine ILIKE '%.dat' OR CommandLine ILIKE '%.dat'' OR CommandLine ILIKE '%.dat\"' OR CommandLine ILIKE '%.msi' OR CommandLine ILIKE '%.msi'' OR CommandLine ILIKE '%.msi\"' OR CommandLine ILIKE '%.bat' OR CommandLine ILIKE '%.bat'' OR CommandLine ILIKE '%.bat\"' OR CommandLine ILIKE '%.exe' OR CommandLine ILIKE '%.exe'' OR CommandLine ILIKE '%.exe\"' OR CommandLine ILIKE '%.vbs' OR CommandLine ILIKE '%.vbs'' OR CommandLine ILIKE '%.vbs\"' OR CommandLine ILIKE '%.vbe' OR CommandLine ILIKE '%.vbe'' OR CommandLine ILIKE '%.vbe\"' OR CommandLine ILIKE '%.hta' OR CommandLine ILIKE '%.hta'' OR CommandLine ILIKE '%.hta\"' OR CommandLine ILIKE '%.dll' OR CommandLine ILIKE '%.dll'' OR CommandLine ILIKE '%.dll\"' OR CommandLine ILIKE '%.psm1' OR CommandLine ILIKE '%.psm1'' OR CommandLine ILIKE '%.psm1\"')) AND ((REGEXP_LIKE(CommandLine, '\s-O\s')) OR (CommandLine ILIKE '%--output-document%')) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\wget.exe') OR (OriginalFileName = 'wget.exe')) AND (REGEXP_LIKE(CommandLine, '://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')))
