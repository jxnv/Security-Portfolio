-- Title: Execute From Alternate Data Streams
-- ID: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-09-01
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%txt:%') AND (((CommandLine LIKE '%esentutl %' AND CommandLine LIKE '% /y %' AND CommandLine LIKE '% /d %' AND CommandLine LIKE '% /o %')) OR ((CommandLine LIKE '%makecab %' AND CommandLine LIKE '%.cab%')) OR ((CommandLine LIKE '%reg %' AND CommandLine LIKE '% export %')) OR ((CommandLine LIKE '%regedit %' AND CommandLine LIKE '% /E %')) OR ((CommandLine LIKE '%type %' AND CommandLine LIKE '% > %'))))
