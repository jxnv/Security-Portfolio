-- Title: Suspicious Service Installation Script
-- ID: 70f00d10-60b2-4f34-b9a0-dc3df3fe762a
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2022-03-18
-- Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
-- Description: Detects suspicious service installation scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ImagePath ILIKE '%cscript%' OR ImagePath ILIKE '%mshta%' OR ImagePath ILIKE '%powershell%' OR ImagePath ILIKE '%pwsh%' OR ImagePath ILIKE '%regsvr32%' OR ImagePath ILIKE '%rundll32%' OR ImagePath ILIKE '%wscript%')) AND ((ImagePath ILIKE '% -c %' OR ImagePath ILIKE '% -r %' OR ImagePath ILIKE '% -k %')) AND (Provider_Name = 'Service Control Manager' AND EventID = 7045))
