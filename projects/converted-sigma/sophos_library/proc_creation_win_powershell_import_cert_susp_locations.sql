-- Title: Root Certificate Installed From Susp Locations
-- ID: 5f6a601c-2ecb-498b-9c33-660362323afa
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.defense-impairment, attack.t1553.004
-- Description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%Import-Certificate%' AND CommandLine ILIKE '% -FilePath %' AND CommandLine ILIKE '%Cert:\\LocalMachine\\Root%') AND (CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%:\\Windows\\TEMP\\%' OR CommandLine ILIKE '%\\Desktop\\%' OR CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Perflogs\\%' OR CommandLine ILIKE '%:\\Users\\Public\\%'))
