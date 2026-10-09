-- Title: Suspicious File Download From IP Via Wget.EXE - Paths
-- ID: 40aa399c-7b02-4715-8e5f-73572b493f33
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-23
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads directly from IP addresses and stored in suspicious locations using Wget.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((REGEXP_LIKE(CommandLine, '\s-O\s')) OR (CommandLine ILIKE '%--output-document%')) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\wget.exe') OR (OriginalFileName = 'wget.exe')) AND (REGEXP_LIKE(CommandLine, '://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')) AND (((CommandLine ILIKE '%:\\PerfLogs\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%' OR CommandLine ILIKE '%:\\Windows\\Help\\%' OR CommandLine ILIKE '%:\\Windows\\Temp\\%' OR CommandLine ILIKE '%\\Temporary Internet%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Favorites\\%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Favourites\\%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Contacts\\%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\Pictures\\%'))))
