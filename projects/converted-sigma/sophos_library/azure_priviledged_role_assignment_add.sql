-- Title: User Added To Privilege Role
-- ID: 49a268a4-72f4-4e38-8a7b-885be690c5b5
-- Status: test
-- Level: high
-- Author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date: 2022-08-06
-- Tags: attack.persistence, attack.initial-access, attack.privilege-escalation, attack.stealth, attack.t1078.004
-- Description: Detects when a user is added to a privileged role.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((properties.message = 'Add eligible member (permanent)' OR properties.message = 'Add eligible member (eligible)'))
