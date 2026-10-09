-- Title: Potential Credential Dumping Via WER
-- ID: 9a4ccd1a-3526-4d99-b980-9f9c5d3a6ff3
-- Status: test
-- Level: high
-- Author: @pbssubhash , Nasreddine Bencherchali
-- Date: 2022-12-08
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects potential credential dumping via Windows Error Reporting LSASS Shtinkering technique which uses the Windows Error Reporting to dump lsass
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((ParentUser LIKE '%AUTHORI%' OR ParentUser LIKE '%AUTORI%') AND (User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%') AND (CommandLine LIKE '% -u -p %' AND CommandLine LIKE '% -ip %' AND CommandLine LIKE '% -s %')) AND ((Image="*\\Werfault.exe") OR (OriginalFileName = 'WerFault.exe'))) AND NOT ((ParentImage = 'C:\\Windows\\System32\\lsass.exe')))
