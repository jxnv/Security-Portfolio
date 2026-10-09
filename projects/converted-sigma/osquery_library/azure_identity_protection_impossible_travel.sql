-- Title: Impossible Travel
-- ID: b2572bf9-e20a-4594-b528-40bde666525a
-- Status: test
-- Level: high
-- Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date: 2023-09-03
-- Tags: attack.stealth, attack.t1078, attack.persistence, attack.privilege-escalation, attack.initial-access
-- Description: Identifies user activities originating from geographically distant locations within a time period shorter than the time it takes to travel from the first location to the second.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (riskEventType = 'impossibleTravel')
