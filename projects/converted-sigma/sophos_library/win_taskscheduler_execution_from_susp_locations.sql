-- Title: Scheduled Task Executed From A Suspicious Location
-- ID: 424273ea-7cf8-43a6-b712-375f925e481f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
-- Description: Detects the execution of Scheduled Tasks where the Program being run is located in a suspicious location or it's an unusale program to be run from a Scheduled Task
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 129 AND (Path ILIKE '%C:\\Windows\\Temp\\%' OR Path ILIKE '%\\AppData\\Local\\Temp\\%' OR Path ILIKE '%\\Desktop\\%' OR Path ILIKE '%\\Downloads\\%' OR Path ILIKE '%\\Users\\Public\\%' OR Path ILIKE '%C:\\Temp\\%'))
