-- Title: Unfamiliar Sign-In Properties
-- ID: 128faeef-79dd-44ca-b43c-a9e236a60f49
-- Status: test
-- Level: high
-- Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date: 2023-09-03
-- Tags: attack.stealth, attack.t1078, attack.persistence, attack.privilege-escalation, attack.initial-access
-- Description: Detects sign-in with properties that are unfamiliar to the user. The detection considers past sign-in history to look for anomalous sign-ins.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (riskEventType = 'unfamiliarFeatures')
