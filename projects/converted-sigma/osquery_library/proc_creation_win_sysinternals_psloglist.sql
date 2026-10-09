-- Title: Suspicious Use of PsLogList
-- ID: aae1243f-d8af-40d8-ab20-33fc6d0c55bc
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-18
-- Tags: attack.discovery, attack.t1087, attack.t1087.001, attack.t1087.002
-- Description: Detects usage of the PsLogList utility to dump event log in order to extract admin accounts and perform account discovery or delete events logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% security%' OR CommandLine LIKE '% application%' OR CommandLine LIKE '% system%')) AND ((CommandLine LIKE '% -d%' OR CommandLine LIKE '% -x%' OR CommandLine LIKE '% -s%' OR CommandLine LIKE '% -c%' OR CommandLine LIKE '% -g%')) AND ((OriginalFileName = 'psloglist.exe') OR ((Image="*\\psloglist.exe" OR Image="*\\psloglist64.exe" OR Image="*\\psloglist64a.exe"))))
