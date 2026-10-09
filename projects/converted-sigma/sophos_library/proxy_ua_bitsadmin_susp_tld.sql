-- Title: Bitsadmin to Uncommon TLD
-- ID: 9eb68894-7476-4cd6-8752-23b51f5883a7
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Tim Shelton
-- Date: 2019-03-07
-- Tags: attack.command-and-control, attack.execution, attack.stealth, attack.t1071.001, attack.persistence, attack.t1197, attack.s0190
-- Description: Detects Bitsadmin connections to domains with uncommon TLDs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((c-useragent ILIKE 'Microsoft BITS/%') AND NOT (((cs-host ILIKE '%.com' OR cs-host ILIKE '%.microsoft' OR cs-host ILIKE '%.net' OR cs-host ILIKE '%.org' OR cs-host ILIKE '%.scdn.co' OR cs-host ILIKE '%.sfx.ms'))))
