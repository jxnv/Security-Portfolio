-- Title: Potential Webshell Creation On Static Website
-- ID: 39f1f9f2-9636-45de-98f6-a4046aa8e4b9
-- Status: test
-- Level: medium
-- Author: Beyu Denis, oscd.community, Tim Shelton, Thurein Oo
-- Date: 2019-10-22
-- Tags: attack.persistence, attack.t1505.003
-- Description: Detects the creation of files with certain extensions on a static web site. This can be indicative of potential uploads of a web shell.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((((TargetFilename LIKE '%.ashx%' OR TargetFilename LIKE '%.asp%' OR TargetFilename LIKE '%.ph%' OR TargetFilename LIKE '%.soap%')) AND (TargetFilename LIKE '%\\inetpub\\wwwroot\\%')) OR ((TargetFilename LIKE '%.ph%') AND ((TargetFilename LIKE '%\\www\\%' OR TargetFilename LIKE '%\\htdocs\\%' OR TargetFilename LIKE '%\\html\\%')))) AND NOT (((TargetFilename LIKE '%\\xampp%') OR (Image = 'System') OR ((TargetFilename LIKE '%\\AppData\\Local\\Temp\\%' OR TargetFilename LIKE '%\\Windows\\Temp\\%')))))
