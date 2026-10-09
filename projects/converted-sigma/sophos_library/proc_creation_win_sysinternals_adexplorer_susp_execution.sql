-- Title: Suspicious Active Directory Database Snapshot Via ADExplorer
-- ID: ef61af62-bc74-4f58-b49b-626448227652
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-14
-- Tags: attack.discovery, attack.t1087.002, attack.t1069.002, attack.t1482
-- Description: Detects the execution of Sysinternals ADExplorer with the "-snapshot" flag in order to save a local copy of the active directory database to a suspicious directory. This can be used by attackers to extract data for Bloodhound, usernames for password spraying or use the meta data for social engineering. The snapshot doesn't contain password hashes but there have been cases, where administrators put passwords in the comment field.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%snapshot%') AND (((Image ILIKE '%\\ADExp.exe' OR Image ILIKE '%\\ADExplorer.exe' OR Image ILIKE '%\\ADExplorer64.exe' OR Image ILIKE '%\\ADExplorer64a.exe')) OR (OriginalFileName = 'AdExp') OR (Description = 'Active Directory Editor') OR (Product = 'Sysinternals ADExplorer')) AND ((CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%\\AppData\\%' OR CommandLine ILIKE '%\\Windows\\Temp\\%')))
