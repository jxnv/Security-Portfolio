-- Title: Bitsadmin to Uncommon IP Server Address
-- ID: 8ccd35a2-1c7c-468b-b568-ac6cdf80eec3
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-10
-- Tags: attack.command-and-control, attack.execution, attack.stealth, attack.t1071.001, attack.persistence, attack.t1197, attack.s0190
-- Description: Detects Bitsadmin connections to IP addresses instead of FQDN names
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (c-useragent ILIKE 'Microsoft BITS/%' AND (cs-host ILIKE '%1' OR cs-host ILIKE '%2' OR cs-host ILIKE '%3' OR cs-host ILIKE '%4' OR cs-host ILIKE '%5' OR cs-host ILIKE '%6' OR cs-host ILIKE '%7' OR cs-host ILIKE '%8' OR cs-host ILIKE '%9'))
