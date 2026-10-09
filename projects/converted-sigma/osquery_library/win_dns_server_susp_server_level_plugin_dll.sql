-- Title: DNS Server Error Failed Loading the ServerLevelPluginDLL
-- ID: cbe51394-cd93-4473-b555-edf0144952d9
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-05-08
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '150' OR EventID = '770' OR EventID = '771'))
