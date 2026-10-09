-- Title: Suspicious File Download From IP Via Curl.EXE
-- ID: 5cb299fc-5fb1-4d07-b989-0644c68b6043
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-27
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads directly from IP addresses using curl.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.bat' OR CommandLine ILIKE '%.bat\"' OR CommandLine ILIKE '%.dat' OR CommandLine ILIKE '%.dat\"' OR CommandLine ILIKE '%.dll' OR CommandLine ILIKE '%.dll\"' OR CommandLine ILIKE '%.exe' OR CommandLine ILIKE '%.exe\"' OR CommandLine ILIKE '%.gif' OR CommandLine ILIKE '%.gif\"' OR CommandLine ILIKE '%.hta' OR CommandLine ILIKE '%.hta\"' OR CommandLine ILIKE '%.jpeg' OR CommandLine ILIKE '%.jpeg\"' OR CommandLine ILIKE '%.log' OR CommandLine ILIKE '%.log\"' OR CommandLine ILIKE '%.msi' OR CommandLine ILIKE '%.msi\"' OR CommandLine ILIKE '%.png' OR CommandLine ILIKE '%.png\"' OR CommandLine ILIKE '%.ps1' OR CommandLine ILIKE '%.ps1\"' OR CommandLine ILIKE '%.psm1' OR CommandLine ILIKE '%.psm1\"' OR CommandLine ILIKE '%.vbe' OR CommandLine ILIKE '%.vbe\"' OR CommandLine ILIKE '%.vbs' OR CommandLine ILIKE '%.vbs\"' OR CommandLine ILIKE '%.bat'' OR CommandLine ILIKE '%.dat'' OR CommandLine ILIKE '%.dll'' OR CommandLine ILIKE '%.exe'' OR CommandLine ILIKE '%.gif'' OR CommandLine ILIKE '%.hta'' OR CommandLine ILIKE '%.jpeg'' OR CommandLine ILIKE '%.log'' OR CommandLine ILIKE '%.msi'' OR CommandLine ILIKE '%.png'' OR CommandLine ILIKE '%.ps1'' OR CommandLine ILIKE '%.psm1'' OR CommandLine ILIKE '%.vbe'' OR CommandLine ILIKE '%.vbs'')) AND ((CommandLine ILIKE '% -O%' OR CommandLine ILIKE '%--remote-name%' OR CommandLine ILIKE '%--output%')) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\curl.exe') OR (OriginalFileName = 'curl.exe')) AND (REGEXP_LIKE(CommandLine, '://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')))
