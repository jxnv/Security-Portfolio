-- Title: Potential Perl Reverse Shell Execution
-- ID: 259df6bc-003f-4306-9f54-4ff1a08fa38e
-- Status: test
-- Level: high
-- Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-07
-- Tags: attack.execution
-- Description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%fdopen(%' AND CommandLine LIKE '%::Socket::INET%')) OR ((CommandLine LIKE '%Socket%' AND CommandLine LIKE '%connect%' AND CommandLine LIKE '%open%' AND CommandLine LIKE '%exec%'))) AND (Image="*/perl" AND CommandLine LIKE '% -e %'))
