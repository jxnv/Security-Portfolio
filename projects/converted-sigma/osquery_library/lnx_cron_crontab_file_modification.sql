-- Title: Modifying Crontab
-- ID: af202fd3-7bff-4212-a25a-fb34606cfcbe
-- Status: test
-- Level: medium
-- Author: Pawel Mazur
-- Date: 2022-04-16
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.003
-- Description: Detects suspicious modification of crontab file.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ("REPLACE")
