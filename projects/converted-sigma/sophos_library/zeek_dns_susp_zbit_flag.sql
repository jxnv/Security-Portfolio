-- Title: Suspicious DNS Z Flag Bit Set
-- ID: ede05abc-2c9e-4624-9944-9ff17fdc0bf5
-- Status: test
-- Level: medium
-- Author: @neu5ron, SOC Prime Team, Corelight
-- Date: 2021-05-04
-- Tags: attack.t1095, attack.t1571, attack.command-and-control
-- Description: The DNS Z flag is bit within the DNS protocol header that is, per the IETF design, meant to be used reserved (unused).
-- Although recently it has been used in DNSSec, the value being set to anything other than 0 should be rare.
-- Otherwise if it is set to non 0 and DNSSec is being used, then excluding the legitimate domains is low effort and high reward.
-- Determine if multiple of these files were accessed in a short period of time to further enhance the possibility of seeing if this was a one off or the possibility of larger sensitive file gathering.
-- This Sigma query is designed to accompany the Corelight Threat Hunting Guide, which can be found here: https://www3.corelight.com/corelights-introductory-guide-to-threat-hunting-with-zeek-bro-logs'
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (NOT ((Z = 0)) AND (query ILIKE '%.%') AND NOT ((((query ILIKE '%.arpa' OR query ILIKE '%.local' OR query ILIKE '%.ultradns.net' OR query ILIKE '%.twtrdns.net' OR query ILIKE '%.azuredns-prd.info' OR query ILIKE '%.azure-dns.com' OR query ILIKE '%.azuredns-ff.info' OR query ILIKE '%.azuredns-ff.org' OR query ILIKE '%.azuregov-dns.org')) OR ((qtype_name = 'ns' OR qtype_name = 'mx')) OR (answers ILIKE '%\\\\x00') OR ((id.resp_p = 137 OR id.resp_p = 138 OR id.resp_p = 139)))))
