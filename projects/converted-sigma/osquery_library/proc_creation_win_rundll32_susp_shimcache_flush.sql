-- Title: ShimCache Flush
-- ID: b0524451-19af-4efa-a46f-562a977f792e
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-02-01
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects actions that clear the local ShimCache and remove forensic evidence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%rundll32%' AND CommandLine LIKE '%apphelp.dll%')) AND ((CommandLine LIKE '%ShimFlushCache%' OR CommandLine LIKE '%#250%'))) OR (((CommandLine LIKE '%rundll32%' AND CommandLine LIKE '%kernel32.dll%')) AND ((CommandLine LIKE '%BaseFlushAppcompatCache%' OR CommandLine LIKE '%#46%'))))
