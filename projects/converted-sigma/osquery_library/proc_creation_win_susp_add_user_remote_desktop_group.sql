-- Title: User Added to Remote Desktop Users Group
-- ID: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-12-06
-- Tags: attack.initial-access, attack.persistence, attack.lateral-movement, attack.t1133, attack.t1136.001, attack.t1021.001
-- Description: Detects addition of users to the local Remote Desktop Users group via "Net" or "Add-LocalGroupMember".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Remote Desktop Users%' OR CommandLine LIKE '%Utilisateurs du Bureau à distance%' OR CommandLine LIKE '%Usuarios de escritorio remoto%')) AND (((CommandLine LIKE '%localgroup %' AND CommandLine LIKE '% /add%')) OR ((CommandLine LIKE '%Add-LocalGroupMember %' AND CommandLine LIKE '% -Group %'))))
