-- Title: Potential Webshell Creation On Static Website
-- ID: 39f1f9f2-9636-45de-98f6-a4046aa8e4b9
-- Status: test
-- Level: medium
-- Author: Beyu Denis, oscd.community, Tim Shelton, Thurein Oo
-- Date: 2019-10-22
-- Tags: attack.persistence, attack.t1505.003
-- Description: Detects the creation of files with certain extensions on a static web site. This can be indicative of potential uploads of a web shell.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((((TargetFilename ILIKE '%.ashx%' OR TargetFilename ILIKE '%.asp%' OR TargetFilename ILIKE '%.ph%' OR TargetFilename ILIKE '%.soap%')) AND (TargetFilename ILIKE '%\\inetpub\\wwwroot\\%')) OR ((TargetFilename ILIKE '%.ph%') AND ((TargetFilename ILIKE '%\\www\\%' OR TargetFilename ILIKE '%\\htdocs\\%' OR TargetFilename ILIKE '%\\html\\%')))) AND NOT (((TargetFilename ILIKE '%\\xampp%') OR (Image = 'System') OR ((TargetFilename ILIKE '%\\AppData\\Local\\Temp\\%' OR TargetFilename ILIKE '%\\Windows\\Temp\\%')))))
