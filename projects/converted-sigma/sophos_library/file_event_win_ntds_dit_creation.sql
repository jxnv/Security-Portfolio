-- Title: NTDS.DIT Created
-- ID: 0b8baa3f-575c-46ee-8715-d6f28cc7d33c
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-05
-- Tags: attack.credential-access, attack.t1003.003
-- Description: Detects creation of a file named "ntds.dit" (Active Directory Database)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetFilename ILIKE '%ntds.dit')
