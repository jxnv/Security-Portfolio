-- Title: New User Created Via Net.EXE With Never Expire Option
-- ID: b9f0e6f5-09b4-4358-bae4-08408705bd5c
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-12
-- Tags: attack.persistence, attack.t1136.001
-- Description: Detects creation of local users via the net.exe command with the option "never expire"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%user%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%expires:never%')) AND (((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe')) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))))
