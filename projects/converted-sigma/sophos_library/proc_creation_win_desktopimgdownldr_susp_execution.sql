-- Title: Suspicious Desktopimgdownldr Command
-- ID: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2020-07-03
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% /lockscreenurl:%') AND NOT (((CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.png%')))) OR ((CommandLine ILIKE '%reg delete%' AND CommandLine ILIKE '%\\PersonalizationCSP%')))
