-- Title: Uncommon Svchost Parent Process
-- ID: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-08-15
-- Tags: attack.stealth, attack.t1036.005
-- Description: Detects an uncommon svchost parent process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\svchost.exe') AND NOT ((((ParentImage ILIKE '%\\Mrt.exe' OR ParentImage ILIKE '%\\MsMpEng.exe' OR ParentImage ILIKE '%\\ngen.exe' OR ParentImage ILIKE '%\\rpcnet.exe' OR ParentImage ILIKE '%\\services.exe' OR ParentImage ILIKE '%\\TiWorker.exe')) OR ((ParentImage = '-' OR ParentImage = '')) OR (ParentImage IS NULL))))
