-- Title: Potential Download/Upload Activity Using Type Command
-- ID: aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-14
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects usage of the "type" command to download/upload data from WebDAV server
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%type \\\\\\\\%' AND CommandLine ILIKE '% > %')) OR ((CommandLine ILIKE '%type %' AND CommandLine ILIKE '% > \\\\\\\\%')))
