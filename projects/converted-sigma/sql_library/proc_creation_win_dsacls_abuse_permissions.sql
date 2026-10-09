-- Title: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
-- ID: 01c42d3c-242d-4655-85b2-34f1739632f7
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.stealth, attack.t1218
-- Description: Detects usage of Dsacls to grant over permissive permissions
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% /G %') AND ((Image ILIKE '%\\dsacls.exe') OR (OriginalFileName = 'DSACLS.EXE')) AND ((CommandLine ILIKE '%GR%' OR CommandLine ILIKE '%GE%' OR CommandLine ILIKE '%GW%' OR CommandLine ILIKE '%GA%' OR CommandLine ILIKE '%WP%' OR CommandLine ILIKE '%WD%')))
