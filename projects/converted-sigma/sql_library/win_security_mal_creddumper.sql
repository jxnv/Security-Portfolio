-- Title: Credential Dumping Tools Service Execution - Security
-- ID: f0d1feba-4344-4ca9-8121-a6c97bd6df52
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
-- Date: 2017-03-05
-- Tags: attack.credential-access, attack.execution, attack.t1003.001, attack.t1003.002, attack.t1003.004, attack.t1003.005, attack.t1003.006, attack.t1569.002, attack.s0005
-- Description: Detects well-known credential dumping tools execution via service execution events
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4697 AND (ServiceFileName ILIKE '%cachedump%' OR ServiceFileName ILIKE '%dumpsvc%' OR ServiceFileName ILIKE '%fgexec%' OR ServiceFileName ILIKE '%gsecdump%' OR ServiceFileName ILIKE '%mimidrv%' OR ServiceFileName ILIKE '%pwdump%' OR ServiceFileName ILIKE '%servpw%'))
