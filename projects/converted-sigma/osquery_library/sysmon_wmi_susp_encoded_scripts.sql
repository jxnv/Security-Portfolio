-- Title: Suspicious Encoded Scripts in a WMI Consumer
-- ID: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-09-01
-- Tags: attack.privilege-escalation, attack.execution, attack.t1047, attack.persistence, attack.t1546.003
-- Description: Detects suspicious encoded payloads in WMI Event Consumers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Destination LIKE '%V3JpdGVQcm9jZXNzTWVtb3J5%' OR Destination LIKE '%dyaXRlUHJvY2Vzc01lbW9ye%' OR Destination LIKE '%Xcml0ZVByb2Nlc3NNZW1vcn%' OR Destination LIKE '%VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG%' OR Destination LIKE '%RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl%' OR Destination LIKE '%UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ%' OR Destination LIKE '%VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy%' OR Destination LIKE '%RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlciBXaW4zM%' OR Destination LIKE '%UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZXIgV2luMz%'))
