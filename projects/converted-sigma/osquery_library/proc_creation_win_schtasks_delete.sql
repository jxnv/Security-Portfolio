-- Title: Delete Important Scheduled Task
-- ID: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.impact, attack.t1489
-- Description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/delete%' OR CommandLine LIKE '%-delete%')) AND ((CommandLine LIKE '%\\Windows\\BitLocker%' OR CommandLine LIKE '%\\Windows\\ExploitGuard%' OR CommandLine LIKE '%\\Windows\\SystemRestore\\SR%' OR CommandLine LIKE '%\\Windows\\UpdateOrchestrator\\%' OR CommandLine LIKE '%\\Windows\\Windows Defender\\%' OR CommandLine LIKE '%\\Windows\\WindowsBackup\\%' OR CommandLine LIKE '%\\Windows\\WindowsUpdate\\%')) AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')))
