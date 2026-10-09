-- Title: Privileged Account Creation
-- ID: f7b5b004-dece-46e4-a4a5-f6fd0e1c6947
-- Status: test
-- Level: medium
-- Author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H', Tim Shelton
-- Date: 2022-08-11
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1078.004
-- Description: Detects when a new admin is created.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((properties.message ILIKE '%Add user%' AND properties.message ILIKE '%Add member to role%') AND Status = 'Success')
