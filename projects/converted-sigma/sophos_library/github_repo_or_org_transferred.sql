-- Title: Github Repository/Organization Transferred
-- ID: 04ad83ef-1a37-4c10-b57a-81092164bf33
-- Status: test
-- Level: medium
-- Author: Romain Gaillard (@romain-gaillard)
-- Date: 2024-07-29
-- Tags: attack.persistence, attack.exfiltration, attack.t1020, attack.t1537
-- Description: Detects when a repository or an organization is being transferred to another location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((action = 'migration.create' OR action = 'org.transfer_outgoing' OR action = 'org.transfer' OR action = 'repo.transfer_outgoing'))
