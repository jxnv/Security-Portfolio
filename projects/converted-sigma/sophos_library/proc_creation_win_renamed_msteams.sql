-- Title: Renamed Microsoft Teams Execution
-- ID: 88f46b67-14d4-4f45-ac2c-d66984f22191
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-07-12
-- Tags: attack.stealth
-- Description: Detects the execution of a renamed Microsoft Teams binary.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((OriginalFileName = 'msteams.exe' OR OriginalFileName = 'teams.exe')) AND NOT (((Image ILIKE '%\\msteams.exe' OR Image ILIKE '%\\teams.exe'))))
