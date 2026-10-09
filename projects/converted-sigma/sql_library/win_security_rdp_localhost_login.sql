-- Title: RDP Login from Localhost
-- ID: 51e33403-2a37-4d66-a574-1fda1782cc31
-- Status: test
-- Level: high
-- Author: Thomas Patzke
-- Date: 2019-01-28
-- Tags: attack.lateral-movement, car.2013-07-002, attack.t1021.001
-- Description: RDP login with localhost source address may be a tunnelled login
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4624 AND LogonType = 10 AND (IpAddress = '::1' OR IpAddress = '127.0.0.1'))
