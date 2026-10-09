-- Title: Disable Important Scheduled Task
-- ID: 9ac94dc8-9042-493c-ba45-3b5e7c86b980
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems), X__Junior
-- Date: 2021-12-26
-- Tags: attack.impact, attack.t1489
-- Description: Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%/disable%' OR CommandLine ILIKE '%-disable%')) AND ((CommandLine ILIKE '%\\Windows\\BitLocker%' OR CommandLine ILIKE '%\\Windows\\ExploitGuard%' OR CommandLine ILIKE '%\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh%' OR CommandLine ILIKE '%\\Windows\\SystemRestore\\SR%' OR CommandLine ILIKE '%\\Windows\\UpdateOrchestrator\\%' OR CommandLine ILIKE '%\\Windows\\Windows Defender\\%' OR CommandLine ILIKE '%\\Windows\\WindowsBackup\\%' OR CommandLine ILIKE '%\\Windows\\WindowsUpdate\\%')) AND ((Image ILIKE '%\\schtasks.exe') OR (OriginalFileName = 'schtasks.exe')))
