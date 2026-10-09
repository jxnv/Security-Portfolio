-- Title: Microsoft IIS Service Account Password Dumped
-- ID: 2d3cdeec-c0db-45b4-aa86-082f7eb75701
-- Status: test
-- Level: high
-- Author: Tim Rauch, Janantha Marasinghe, Elastic (original idea)
-- Date: 2022-11-08
-- Tags: attack.credential-access, attack.t1003
-- Description: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%list %') AND ((Image="*\\appcmd.exe") OR (OriginalFileName = 'appcmd.exe'))) AND (((CommandLine LIKE '% /config%' OR CommandLine LIKE '% /xml%' OR CommandLine LIKE '% -config%' OR CommandLine LIKE '% -xml%')) OR (((CommandLine LIKE '% /@t%' OR CommandLine LIKE '% /text%' OR CommandLine LIKE '% /show%' OR CommandLine LIKE '% -@t%' OR CommandLine LIKE '% -text%' OR CommandLine LIKE '% -show%')) AND ((CommandLine LIKE '%:\\*%' OR CommandLine LIKE '%password%')))))
