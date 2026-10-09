-- Title: LSASS Dump Keyword In CommandLine
-- ID: ffa6861c-4461-4f59-8a41-578c39f3f23e
-- Status: test
-- Level: high
-- Author: E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-10-24
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects the presence of the keywords "lsass" and ".dmp" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%lsass.dmp%' OR CommandLine ILIKE '%lsass.zip%' OR CommandLine ILIKE '%lsass.rar%' OR CommandLine ILIKE '%Andrew.dmp%' OR CommandLine ILIKE '%Coredump.dmp%' OR CommandLine ILIKE '%NotLSASS.zip%' OR CommandLine ILIKE '%lsass_2%' OR CommandLine ILIKE '%lsassdump%' OR CommandLine ILIKE '%lsassdmp%')) OR ((CommandLine ILIKE '%lsass%' AND CommandLine ILIKE '%.dmp%')) OR ((CommandLine ILIKE '%SQLDmpr%' AND CommandLine ILIKE '%.mdmp%')) OR ((CommandLine ILIKE '%nanodump%' AND CommandLine ILIKE '%.dmp%')))
