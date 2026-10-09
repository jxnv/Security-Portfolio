-- Title: Wdigest Enable UseLogonCredential
-- ID: d6a9b252-c666-4de6-8806-5561bbbd3bdc
-- Status: test
-- Level: high
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2019-09-12
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetObject ILIKE '%WDigest\\UseLogonCredential' AND Details = 'DWORD (0x00000001)')
