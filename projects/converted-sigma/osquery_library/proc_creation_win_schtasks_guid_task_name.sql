-- Title: Suspicious Scheduled Task Name As GUID
-- ID: ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-31
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects creation of a scheduled task with a GUID like name
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%}\"%' OR CommandLine LIKE '%}'%' OR CommandLine LIKE '%} %')) AND (Image="*\\schtasks.exe" AND CommandLine LIKE '%/Create %') AND ((CommandLine LIKE '%/TN \"{%' OR CommandLine LIKE '%/TN '{%' OR CommandLine LIKE '%/TN {%')))
