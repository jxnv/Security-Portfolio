-- Title: Possible DCSync Attack
-- ID: 56fda488-113e-4ce9-8076-afc2457922c3
-- Status: test
-- Level: high
-- Author: Sagie Dulce, Dekel Paz
-- Date: 2022-01-01
-- Tags: attack.t1033, attack.discovery
-- Description: Detects remote RPC calls to MS-DRSR from non DC hosts, which could indicate DCSync / DCShadow attacks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((EventLog = 'RPCFW' AND EventID = 3 AND InterfaceUuid = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2') AND NOT (((OpNum = 0 OR OpNum = 1 OR OpNum = 12))))
