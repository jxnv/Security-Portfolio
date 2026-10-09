-- Title: ShimCache Flush
-- ID: b0524451-19af-4efa-a46f-562a977f792e
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-02-01
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects actions that clear the local ShimCache and remove forensic evidence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%rundll32%' AND CommandLine ILIKE '%apphelp.dll%')) AND ((CommandLine ILIKE '%ShimFlushCache%' OR CommandLine ILIKE '%#250%'))) OR (((CommandLine ILIKE '%rundll32%' AND CommandLine ILIKE '%kernel32.dll%')) AND ((CommandLine ILIKE '%BaseFlushAppcompatCache%' OR CommandLine ILIKE '%#46%'))))
