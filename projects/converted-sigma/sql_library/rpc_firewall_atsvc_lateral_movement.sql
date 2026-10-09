-- Title: Remote Schedule Task Lateral Movement via ATSvc
-- ID: 0fcd1c79-4eeb-4746-aba9-1b458f7a79cb
-- Status: test
-- Level: high
-- Author: Sagie Dulce, Dekel Paz
-- Date: 2022-01-01
-- Tags: attack.privilege-escalation, attack.lateral-movement, attack.execution, attack.persistence, attack.t1053, attack.t1053.002
-- Description: Detects remote RPC calls to create or execute a scheduled task via ATSvc
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventLog = 'RPCFW' AND EventID = 3 AND InterfaceUuid = '1ff70682-0a51-30e8-076d-740be8cee98b' AND (OpNum = 0 OR OpNum = 1))
