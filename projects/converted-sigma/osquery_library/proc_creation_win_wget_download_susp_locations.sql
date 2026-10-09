-- Title: Suspicious File Download From IP Via Wget.EXE - Paths
-- ID: 40aa399c-7b02-4715-8e5f-73572b493f33
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-23
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads directly from IP addresses and stored in suspicious locations using Wget.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine=regex("\\s-O\\s")) OR (CommandLine LIKE '%--output-document%')) AND (CommandLine LIKE '%http%') AND ((Image="*\\wget.exe") OR (OriginalFileName = 'wget.exe')) AND (CommandLine=regex("://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")) AND (((CommandLine LIKE '%:\\PerfLogs\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Help\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\Temporary Internet%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Favorites\\%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Favourites\\%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Contacts\\%')) OR ((CommandLine LIKE '%:\\Users\\%' AND CommandLine LIKE '%\\Pictures\\%'))))
