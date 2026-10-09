-- Title: Potential Data Exfiltration Activity Via CommandLine Tools
-- ID: 7d1aaf3d-4304-425c-b7c3-162055e0b3ab
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-02
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the use of various CLI utilities exfiltrating data via web requests
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe") AND (CommandLine LIKE '%curl %' OR CommandLine LIKE '%Invoke-RestMethod%' OR CommandLine LIKE '%Invoke-WebRequest%' OR CommandLine LIKE '%irm %' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%wget %') AND (CommandLine LIKE '% -ur%' AND CommandLine LIKE '% -me%' AND CommandLine LIKE '% -b%' AND CommandLine LIKE '% POST %')) OR ((Image="*\\curl.exe" AND CommandLine LIKE '%--ur%') AND ((CommandLine LIKE '% -d %' OR CommandLine LIKE '% --data %'))) OR (Image="*\\wget.exe" AND (CommandLine LIKE '%--post-data%' OR CommandLine LIKE '%--post-file%'))) AND (((CommandLine=regex("net\\s+view") OR CommandLine=regex("sc\\s+query"))) OR ((CommandLine LIKE '%Get-Content%' OR CommandLine LIKE '%GetBytes%' OR CommandLine LIKE '%hostname%' OR CommandLine LIKE '%ifconfig%' OR CommandLine LIKE '%ipconfig%' OR CommandLine LIKE '%netstat%' OR CommandLine LIKE '%nltest%' OR CommandLine LIKE '%qprocess%' OR CommandLine LIKE '%systeminfo%' OR CommandLine LIKE '%tasklist%' OR CommandLine LIKE '%ToBase64String%' OR CommandLine LIKE '%whoami%')) OR ((CommandLine LIKE '%type %' AND CommandLine LIKE '% > %' AND CommandLine LIKE '% C:\\%'))))
