-- Title: Suspicious Scheduled Task Creation Involving Temp Folder
-- ID: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-03-11
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\schtasks.exe' AND (CommandLine ILIKE '% /create %' AND CommandLine ILIKE '% /sc once %' AND CommandLine ILIKE '%\\Temp\\%'))
