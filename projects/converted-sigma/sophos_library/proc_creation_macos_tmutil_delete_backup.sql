-- Title: Time Machine Backup Deletion Attempt Via Tmutil - MacOS
-- ID: 452df256-da78-427a-866f-49fa04417d74
-- Status: test
-- Level: medium
-- Author: Pratinav Chandra
-- Date: 2024-05-29
-- Tags: attack.impact, attack.t1490
-- Description: Detects deletion attempts of MacOS Time Machine backups via the native backup utility "tmutil".
-- An adversary may perform this action before launching a ransonware attack to prevent the victim from restoring their files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%delete%') AND ((Image ILIKE '%/tmutil') OR (CommandLine ILIKE '%tmutil%')))
