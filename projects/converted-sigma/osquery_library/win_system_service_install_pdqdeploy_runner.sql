-- Title: New PDQDeploy Service - Client Side
-- ID: b98a10af-1e1e-44a7-bab2-4cc026917648
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-22
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects PDQDeploy service installation on the target system.
-- When a package is deployed via PDQDeploy it installs a remote service on the target machine with the name "PDQDeployRunner-X" where "X" is an integer starting from 1
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Provider_Name = 'Service Control Manager' AND EventID = '7045') AND ((ImagePath LIKE '%PDQDeployRunner-%') OR (ServiceName="PDQDeployRunner-*")))
