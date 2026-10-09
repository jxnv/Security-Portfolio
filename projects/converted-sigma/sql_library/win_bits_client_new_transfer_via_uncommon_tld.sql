-- Title: BITS Transfer Job With Uncommon Or Suspicious Remote TLD
-- ID: 6d44fb93-e7d2-475c-9d3d-54c9c1e33427
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-10
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
-- Description: Detects a suspicious download using the BITS client from a FQDN that is unusual. Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((EventID = 16403) AND NOT (((RemoteName ILIKE '%.azureedge.net/%' OR RemoteName ILIKE '%.com/%' OR RemoteName ILIKE '%.sfx.ms/%' OR RemoteName ILIKE '%download.mozilla.org/%' OR RemoteName ILIKE '%cdn.onenote.net/%' OR RemoteName ILIKE '%cdn.office.net/%' OR RemoteName ILIKE '%tscdn.m365.static.microsoft/%'))))
