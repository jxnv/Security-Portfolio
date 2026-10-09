-- Title: Azure Firewall Modified or Deleted
-- ID: 512cf937-ea9b-4332-939c-4c2c94baadcd
-- Status: test
-- Level: medium
-- Author: Austin Songer @austinsonger
-- Date: 2021-08-08
-- Tags: attack.impact, attack.defense-impairment, attack.t1686.001
-- Description: Identifies when a firewall is created, modified, or deleted.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((operationName = 'MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE' OR operationName = 'MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE'))
