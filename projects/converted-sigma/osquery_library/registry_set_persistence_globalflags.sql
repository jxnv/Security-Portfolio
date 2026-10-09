-- Title: Potential Persistence Via GlobalFlags
-- ID: 36803969-5421-41ec-b92f-8500f79c23b0
-- Status: test
-- Level: high
-- Author: Karneades, Jonhnathan Ribeiro, Florian Roth
-- Date: 2018-04-11
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.012, car.2013-01-002
-- Description: Detects registry persistence technique using the GlobalFlags and SilentProcessExit keys
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\%' AND TargetObject LIKE '%\\Image File Execution Options\\%' AND TargetObject LIKE '%\\GlobalFlag%')) OR ((TargetObject LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\%' AND TargetObject LIKE '%\\SilentProcessExit\\%') AND (TargetObject LIKE '%\\ReportingMode%' OR TargetObject LIKE '%\\MonitorProcess%')))
