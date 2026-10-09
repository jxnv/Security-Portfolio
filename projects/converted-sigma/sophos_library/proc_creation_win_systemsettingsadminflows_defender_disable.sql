-- Title: Windows Defender Disabled Via SystemSettingsAdminFlows.EXE
-- ID: da92713f-ca2d-4fab-8320-098013d3f43a
-- Status: experimental
-- Level: high
-- Author: Chirag Damani (KPMG India), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-07-01
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the usage of SystemSettingsAdminFlows.exe to disable Windows Defender.
-- SystemSettingsAdminFlows.exe is a legitimate Windows component used for administrative configuration tasks.
-- However, attackers may abuse it to disable Windows Defender as part of their attack chain, especially in the context of ransomware or other malware campaigns.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%defender%') AND ((Image ILIKE '%\\SystemSettingsAdminFlows.exe') OR (OriginalFileName = 'SystemSettingsAdminFlows.EXE'))) AND ((((CommandLine ILIKE '%RTP %' OR CommandLine ILIKE '%RealTimeProtection %' OR CommandLine ILIKE '%DisableEnhancedNotifications %')) AND (CommandLine ILIKE '%1%')) OR (((CommandLine ILIKE '%SubmitSamplesConsent %' OR CommandLine ILIKE '%SpyNetReporting %' OR CommandLine ILIKE '%DisableCDPUserAuthPolicy %')) AND (CommandLine ILIKE '%0%'))))
