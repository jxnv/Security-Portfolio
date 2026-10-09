-- Title: Notepad++ Updater DNS Query to Uncommon Domains
-- ID: 2074e137-1b73-4e2d-88ba-5a3407dbdce0
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-02-02
-- Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
-- Description: Detects when the Notepad++ updater (gup.exe) makes DNS queries to domains that are not part of the known legitimate update infrastructure.
-- This could indicate potential exploitation of the updater mechanism or suspicious network activity that warrants further investigation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Image="*\\gup.exe") AND NOT ((QueryName = 'notepad-plus-plus.org')) AND NOT ((((QueryName="*.githubusercontent.com") OR (QueryName = 'github.com')) OR (QueryName="*.googleapis.com") OR (QueryName="*.sourceforge.net") OR ((QueryName="*.azurewebsites.net" OR QueryName="*block.opendns.com" OR QueryName="*gateway.zscalerthree.net")))))
