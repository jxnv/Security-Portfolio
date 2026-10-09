-- Title: Remote Registry Lateral Movement
-- ID: 35c55673-84ca-4e99-8d09-e334f3c29539
-- Status: test
-- Level: high
-- Author: Sagie Dulce, Dekel Paz
-- Date: 2022-01-01
-- Tags: attack.lateral-movement, attack.defense-impairment, attack.t1112, attack.persistence
-- Description: Detects remote RPC calls to modify the registry and possible execute code
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventLog = 'RPCFW' AND EventID = 3 AND InterfaceUuid = '338cd001-2244-31f1-aaaa-900038001003' AND (OpNum = 6 OR OpNum = 7 OR OpNum = 8 OR OpNum = 13 OR OpNum = 18 OR OpNum = 19 OR OpNum = 21 OR OpNum = 22 OR OpNum = 23 OR OpNum = 35))
