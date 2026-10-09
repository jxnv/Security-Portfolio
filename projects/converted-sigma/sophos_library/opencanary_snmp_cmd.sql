-- Title: OpenCanary - SNMP OID Request
-- ID: e9856028-fd4e-46e6-b3d1-10f7ceb95078
-- Status: test
-- Level: high
-- Author: Security Onion Solutions
-- Date: 2024-03-08
-- Tags: attack.discovery, attack.lateral-movement, attack.t1016, attack.t1021
-- Description: Detects instances where an SNMP service on an OpenCanary node has had an OID request.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (logtype = 13001)
