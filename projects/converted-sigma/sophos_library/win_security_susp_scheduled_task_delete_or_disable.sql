-- Title: Important Scheduled Task Deleted/Disabled
-- ID: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
-- Description: Detects when adversaries stop services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((EventID = 4699 OR EventID = 4701) AND (TaskName ILIKE '%\\Windows\\SystemRestore\\SR%' OR TaskName ILIKE '%\\Windows\\Windows Defender\\%' OR TaskName ILIKE '%\\Windows\\BitLocker%' OR TaskName ILIKE '%\\Windows\\WindowsBackup\\%' OR TaskName ILIKE '%\\Windows\\WindowsUpdate\\%' OR TaskName ILIKE '%\\Windows\\UpdateOrchestrator\\Schedule%' OR TaskName ILIKE '%\\Windows\\ExploitGuard%')) AND NOT ((EventID = 4699 AND SubjectUserName ILIKE '%$' AND TaskName ILIKE '%\\Windows\\Windows Defender\\%')))
