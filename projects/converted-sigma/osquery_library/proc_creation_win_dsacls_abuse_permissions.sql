-- Title: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
-- ID: 01c42d3c-242d-4655-85b2-34f1739632f7
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.stealth, attack.t1218
-- Description: Detects usage of Dsacls to grant over permissive permissions
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% /G %') AND ((Image="*\\dsacls.exe") OR (OriginalFileName = 'DSACLS.EXE')) AND ((CommandLine LIKE '%GR%' OR CommandLine LIKE '%GE%' OR CommandLine LIKE '%GW%' OR CommandLine LIKE '%GA%' OR CommandLine LIKE '%WP%' OR CommandLine LIKE '%WD%')))
