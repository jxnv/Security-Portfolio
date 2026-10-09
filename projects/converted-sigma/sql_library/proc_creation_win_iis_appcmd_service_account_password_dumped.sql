-- Title: Microsoft IIS Service Account Password Dumped
-- ID: 2d3cdeec-c0db-45b4-aa86-082f7eb75701
-- Status: test
-- Level: high
-- Author: Tim Rauch, Janantha Marasinghe, Elastic (original idea)
-- Date: 2022-11-08
-- Tags: attack.credential-access, attack.t1003
-- Description: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%list %') AND ((Image ILIKE '%\\appcmd.exe') OR (OriginalFileName = 'appcmd.exe'))) AND (((CommandLine ILIKE '% /config%' OR CommandLine ILIKE '% /xml%' OR CommandLine ILIKE '% -config%' OR CommandLine ILIKE '% -xml%')) OR (((CommandLine ILIKE '% /@t%' OR CommandLine ILIKE '% /text%' OR CommandLine ILIKE '% /show%' OR CommandLine ILIKE '% -@t%' OR CommandLine ILIKE '% -text%' OR CommandLine ILIKE '% -show%')) AND ((CommandLine ILIKE '%:\\*%' OR CommandLine ILIKE '%password%')))))
