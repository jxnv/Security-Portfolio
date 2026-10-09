-- Title: Important Scheduled Task Deleted/Disabled
-- ID: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
-- Description: Detects when adversaries stop services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((EventID = '4699' OR EventID = '4701') AND (TaskName LIKE '%\\Windows\\SystemRestore\\SR%' OR TaskName LIKE '%\\Windows\\Windows Defender\\%' OR TaskName LIKE '%\\Windows\\BitLocker%' OR TaskName LIKE '%\\Windows\\WindowsBackup\\%' OR TaskName LIKE '%\\Windows\\WindowsUpdate\\%' OR TaskName LIKE '%\\Windows\\UpdateOrchestrator\\Schedule%' OR TaskName LIKE '%\\Windows\\ExploitGuard%')) AND NOT ((EventID = '4699' AND SubjectUserName="*$" AND TaskName LIKE '%\\Windows\\Windows Defender\\%')))
