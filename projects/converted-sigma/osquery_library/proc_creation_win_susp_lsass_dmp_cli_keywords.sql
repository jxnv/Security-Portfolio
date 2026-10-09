-- Title: LSASS Dump Keyword In CommandLine
-- ID: ffa6861c-4461-4f59-8a41-578c39f3f23e
-- Status: test
-- Level: high
-- Author: E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-10-24
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects the presence of the keywords "lsass" and ".dmp" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%lsass.dmp%' OR CommandLine LIKE '%lsass.zip%' OR CommandLine LIKE '%lsass.rar%' OR CommandLine LIKE '%Andrew.dmp%' OR CommandLine LIKE '%Coredump.dmp%' OR CommandLine LIKE '%NotLSASS.zip%' OR CommandLine LIKE '%lsass_2%' OR CommandLine LIKE '%lsassdump%' OR CommandLine LIKE '%lsassdmp%')) OR ((CommandLine LIKE '%lsass%' AND CommandLine LIKE '%.dmp%')) OR ((CommandLine LIKE '%SQLDmpr%' AND CommandLine LIKE '%.mdmp%')) OR ((CommandLine LIKE '%nanodump%' AND CommandLine LIKE '%.dmp%')))
