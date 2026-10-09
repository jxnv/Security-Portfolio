-- Title: Sliver C2 Default Service Installation
-- ID: 31c51af6-e7aa-4da7-84d4-8f32cc580af2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-25
-- Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.t1543.003, attack.t1569.002
-- Description: Detects known malicious service installation that appear in cases in which a Sliver implants execute the PsExec commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Provider_Name = 'Service Control Manager' AND EventID = '7045') AND ((ImagePath=regex("^[a-zA-Z]:\\\\windows\\\\temp\\\\[a-zA-Z0-9]{10}\\.exe")) OR ((ServiceName = 'Sliver' OR ServiceName = 'Sliver implant'))))
