-- Title: Moriya Rootkit - System
-- ID: 25b9c01c-350d-4b95-bed1-836d04a4f324
-- Status: test
-- Level: critical
-- Author: Bhabesh Raj
-- Date: 2021-05-06
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects the use of Moriya rootkit as described in the securelist's Operation TunnelSnake report
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Provider_Name = 'Service Control Manager' AND EventID = '7045' AND ServiceName = 'ZzNetSvc')
