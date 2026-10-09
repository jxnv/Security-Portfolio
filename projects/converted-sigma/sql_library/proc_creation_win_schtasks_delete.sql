-- Title: Delete Important Scheduled Task
-- ID: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.impact, attack.t1489
-- Description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/delete%' OR CommandLine ILIKE '%-delete%')) AND ((CommandLine ILIKE '%\\Windows\\BitLocker%' OR CommandLine ILIKE '%\\Windows\\ExploitGuard%' OR CommandLine ILIKE '%\\Windows\\SystemRestore\\SR%' OR CommandLine ILIKE '%\\Windows\\UpdateOrchestrator\\%' OR CommandLine ILIKE '%\\Windows\\Windows Defender\\%' OR CommandLine ILIKE '%\\Windows\\WindowsBackup\\%' OR CommandLine ILIKE '%\\Windows\\WindowsUpdate\\%')) AND ((Image ILIKE '%\\schtasks.exe') OR (OriginalFileName = 'schtasks.exe')))
