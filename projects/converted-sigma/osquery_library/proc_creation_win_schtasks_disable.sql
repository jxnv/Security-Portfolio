-- Title: Disable Important Scheduled Task
-- ID: 9ac94dc8-9042-493c-ba45-3b5e7c86b980
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems), X__Junior
-- Date: 2021-12-26
-- Tags: attack.impact, attack.t1489
-- Description: Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/disable%' OR CommandLine LIKE '%-disable%')) AND ((CommandLine LIKE '%\\Windows\\BitLocker%' OR CommandLine LIKE '%\\Windows\\ExploitGuard%' OR CommandLine LIKE '%\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh%' OR CommandLine LIKE '%\\Windows\\SystemRestore\\SR%' OR CommandLine LIKE '%\\Windows\\UpdateOrchestrator\\%' OR CommandLine LIKE '%\\Windows\\Windows Defender\\%' OR CommandLine LIKE '%\\Windows\\WindowsBackup\\%' OR CommandLine LIKE '%\\Windows\\WindowsUpdate\\%')) AND ((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')))
