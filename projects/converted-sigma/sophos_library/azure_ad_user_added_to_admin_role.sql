-- Title: User Added to an Administrator's Azure AD Role
-- ID: ebbeb024-5b1d-4e16-9c0c-917f86c708a7
-- Status: test
-- Level: medium
-- Author: Raphaël CALVET, @MetallicHack
-- Date: 2021-10-04
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1098.003, attack.t1078
-- Description: User Added to an Administrator's Azure AD Role
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (operationName = 'Add member to role' AND (properties.targetResources ILIKE '%Admins%' OR properties.targetResources ILIKE '%Administrator%'))
