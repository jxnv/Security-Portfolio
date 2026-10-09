// Title: Remote Registry Lateral Movement
// ID: 35c55673-84ca-4e99-8d09-e334f3c29539
// Status: test
// Level: high
// Author: Sagie Dulce, Dekel Paz
// Date: 2022-01-01
// Tags: attack.lateral-movement, attack.defense-impairment, attack.t1112, attack.persistence
// Description: Detects remote RPC calls to modify the registry and possible execute code
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventLog = "RPCFW" and EventID = 3 and InterfaceUuid = "338cd001-2244-31f1-aaaa-900038001003" and (OpNum = 6 or OpNum = 7 or OpNum = 8 or OpNum = 13 or OpNum = 18 or OpNum = 19 or OpNum = 21 or OpNum = 22 or OpNum = 23 or OpNum = 35))
