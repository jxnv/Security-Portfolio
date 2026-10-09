-- Title: Lsass Memory Dump via Comsvcs DLL
-- ID: a49fa4d5-11db-418c-8473-1e014a8dd462
-- Status: test
-- Level: high
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-10-20
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetImage ILIKE '%\\lsass.exe' AND SourceImage ILIKE '%\\rundll32.exe' AND CallTrace ILIKE '%comsvcs.dll%')
