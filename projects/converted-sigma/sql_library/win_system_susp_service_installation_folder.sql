-- Title: Service Installation in Suspicious Folder
-- ID: 5e993621-67d4-488a-b9ae-b420d08b96cb
-- Status: test
-- Level: medium
-- Author: pH-T (Nextron Systems)
-- Date: 2022-03-18
-- Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
-- Description: Detects service installation in suspicious folder appdata
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Provider_Name = 'Service Control Manager' AND EventID = 7045 AND (ImagePath ILIKE '%\\AppData\\%' OR ImagePath ILIKE '%\\\\\\\\127.0.0.1%' OR ImagePath ILIKE '%\\\\\\\\localhost%')) AND NOT ((ServiceName = 'Zoom Sharing Service' AND ImagePath ILIKE '%:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe%')))
