-- Title: Cisco Clear Logs
-- ID: ceb407f6-8277-439b-951f-e4210e3ed956
-- Status: test
-- Level: high
-- Author: Austin Clark
-- Date: 2019-08-12
-- Tags: attack.stealth, attack.t1070.003
-- Description: Clear command history in network OS which is used for defense evasion
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ("clear logging" OR "clear archive")
