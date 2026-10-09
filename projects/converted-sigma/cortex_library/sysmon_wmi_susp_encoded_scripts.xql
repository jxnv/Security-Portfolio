// Title: Suspicious Encoded Scripts in a WMI Consumer
// ID: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-09-01
// Tags: attack.privilege-escalation, attack.execution, attack.t1047, attack.persistence, attack.t1546.003
// Description: Detects suspicious encoded payloads in WMI Event Consumers
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Destination contains "V3JpdGVQcm9jZXNzTWVtb3J5" or Destination contains "dyaXRlUHJvY2Vzc01lbW9ye" or Destination contains "Xcml0ZVByb2Nlc3NNZW1vcn" or Destination contains "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG" or Destination contains "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl" or Destination contains "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ" or Destination contains "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy" or Destination contains "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlciBXaW4zM" or Destination contains "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZXIgV2luMz"))
