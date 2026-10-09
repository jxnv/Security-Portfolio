-- Title: Potential Perl Reverse Shell Execution
-- ID: 259df6bc-003f-4306-9f54-4ff1a08fa38e
-- Status: test
-- Level: high
-- Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-07
-- Tags: attack.execution
-- Description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%fdopen(%' AND CommandLine ILIKE '%::Socket::INET%')) OR ((CommandLine ILIKE '%Socket%' AND CommandLine ILIKE '%connect%' AND CommandLine ILIKE '%open%' AND CommandLine ILIKE '%exec%'))) AND (Image ILIKE '%/perl' AND CommandLine ILIKE '% -e %'))
