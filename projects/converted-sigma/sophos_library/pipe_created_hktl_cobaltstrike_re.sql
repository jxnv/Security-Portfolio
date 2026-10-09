-- Title: CobaltStrike Named Pipe Pattern Regex
-- ID: 0e7163d4-9e19-4fa7-9be6-000c61aad77a
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-07-30
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055
-- Description: Detects the creation of a named pipe matching a pattern used by CobaltStrike Malleable C2 profiles
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((REGEXP_LIKE(PipeName, '\\mojo\.5688\.8052\.(?:183894939787088877|35780273329370473)[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\wkssvc_?[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\ntsvcs[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\DserNamePipe[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\SearchTextHarvester[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\mypipe-(?:f|h)[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\windows\.update\.manager[0-9a-f]{2,3}')) OR (REGEXP_LIKE(PipeName, '\\ntsvcs_[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\scerpc_?[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\PGMessagePipe[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\MsFteWds[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\f4c3[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\fullduplex_[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\msrpc_[0-9a-f]{4}')) OR (REGEXP_LIKE(PipeName, '\\win\\msrpc_[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\f53f[0-9a-f]{2}$')) OR (REGEXP_LIKE(PipeName, '\\rpc_[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\spoolss_[0-9a-f]{2}')) OR (REGEXP_LIKE(PipeName, '\\Winsock2\\CatalogChangeListener-[0-9a-f]{3}-0,')))
