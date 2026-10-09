-- Title: Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE
-- ID: 07f8bdc2-c9b3-472a-9817-5a670b872f53
-- Status: test
-- Level: high
-- Author: jmallette, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-01-16
-- Tags: attack.credential-access, attack.t1003.005
-- Description: Detects usage of cmdkey to look for cached credentials on the system
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '% -l%') AND ((Image ILIKE '%\\cmdkey.exe') OR (OriginalFileName = 'cmdkey.exe')))
