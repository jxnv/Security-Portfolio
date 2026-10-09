-- Title: Suspicious Scheduled Task Name As GUID
-- ID: ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-31
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects creation of a scheduled task with a GUID like name
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%}\"%' OR CommandLine ILIKE '%}'%' OR CommandLine ILIKE '%} %')) AND (Image ILIKE '%\\schtasks.exe' AND CommandLine ILIKE '%/Create %') AND ((CommandLine ILIKE '%/TN \"{%' OR CommandLine ILIKE '%/TN '{%' OR CommandLine ILIKE '%/TN {%')))
