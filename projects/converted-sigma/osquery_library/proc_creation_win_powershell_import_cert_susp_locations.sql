-- Title: Root Certificate Installed From Susp Locations
-- ID: 5f6a601c-2ecb-498b-9c33-660362323afa
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.defense-impairment, attack.t1553.004
-- Description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%Import-Certificate%' AND CommandLine LIKE '% -FilePath %' AND CommandLine LIKE '%Cert:\\LocalMachine\\Root%') AND (CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\TEMP\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Perflogs\\%' OR CommandLine LIKE '%:\\Users\\Public\\%'))
