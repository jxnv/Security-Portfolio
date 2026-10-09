-- Title: Compress Data and Lock With Password for Exfiltration With WINZIP
-- ID: e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-27
-- Tags: attack.collection, attack.t1560.001
-- Description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -min %' OR CommandLine LIKE '% -a %')) AND (CommandLine LIKE '%-s\"%') AND ((CommandLine LIKE '%winzip.exe%' OR CommandLine LIKE '%winzip64.exe%')))
