-- Title: File Deletion
-- ID: 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57
-- Status: stable
-- Level: informational
-- Author: Ömer Günal, oscd.community
-- Date: 2020-10-07
-- Tags: attack.stealth, attack.t1070.004
-- Description: Detects file deletion using "rm", "shred" or "unlink" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/rm" OR Image="*/shred" OR Image="*/unlink"))
