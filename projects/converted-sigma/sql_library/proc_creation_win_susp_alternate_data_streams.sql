-- Title: Execute From Alternate Data Streams
-- ID: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-09-01
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%txt:%') AND (((CommandLine ILIKE '%esentutl %' AND CommandLine ILIKE '% /y %' AND CommandLine ILIKE '% /d %' AND CommandLine ILIKE '% /o %')) OR ((CommandLine ILIKE '%makecab %' AND CommandLine ILIKE '%.cab%')) OR ((CommandLine ILIKE '%reg %' AND CommandLine ILIKE '% export %')) OR ((CommandLine ILIKE '%regedit %' AND CommandLine ILIKE '% /E %')) OR ((CommandLine ILIKE '%type %' AND CommandLine ILIKE '% > %'))))
