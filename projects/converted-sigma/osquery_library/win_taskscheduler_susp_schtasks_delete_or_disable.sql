-- Title: Important Scheduled Task Deleted or Disabled
-- ID: 9e3cb244-bdb8-4632-8c90-6079c8f4f16d
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2023-01-13
-- Tags: attack.impact, attack.t1489
-- Description: Detects when adversaries try to stop system services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((EventID = '141' OR EventID = '142') AND (TaskName LIKE '%\\Windows\\SystemRestore\\SR%' OR TaskName LIKE '%\\Windows\\Windows Defender\\%' OR TaskName LIKE '%\\Windows\\BitLocker%' OR TaskName LIKE '%\\Windows\\WindowsBackup\\%' OR TaskName LIKE '%\\Windows\\WindowsUpdate\\%' OR TaskName LIKE '%\\Windows\\UpdateOrchestrator\\%' OR TaskName LIKE '%\\Windows\\ExploitGuard%')) AND NOT (((UserName LIKE '%AUTHORI%' OR UserName LIKE '%AUTORI%'))))
