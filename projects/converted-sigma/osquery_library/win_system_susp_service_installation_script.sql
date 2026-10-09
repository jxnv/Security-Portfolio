-- Title: Suspicious Service Installation Script
-- ID: 70f00d10-60b2-4f34-b9a0-dc3df3fe762a
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2022-03-18
-- Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
-- Description: Detects suspicious service installation scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ImagePath LIKE '%cscript%' OR ImagePath LIKE '%mshta%' OR ImagePath LIKE '%powershell%' OR ImagePath LIKE '%pwsh%' OR ImagePath LIKE '%regsvr32%' OR ImagePath LIKE '%rundll32%' OR ImagePath LIKE '%wscript%')) AND ((ImagePath LIKE '% -c %' OR ImagePath LIKE '% -r %' OR ImagePath LIKE '% -k %')) AND (Provider_Name = 'Service Control Manager' AND EventID = '7045'))
