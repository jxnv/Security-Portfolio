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

SELECT * FROM processes WHERE (((CommandLine LIKE '%defender%') AND ((Image="*\\SystemSettingsAdminFlows.exe") OR (OriginalFileName = 'SystemSettingsAdminFlows.EXE'))) AND ((((CommandLine LIKE '%RTP %' OR CommandLine LIKE '%RealTimeProtection %' OR CommandLine LIKE '%DisableEnhancedNotifications %')) AND (CommandLine LIKE '%1%')) OR (((CommandLine LIKE '%SubmitSamplesConsent %' OR CommandLine LIKE '%SpyNetReporting %' OR CommandLine LIKE '%DisableCDPUserAuthPolicy %')) AND (CommandLine LIKE '%0%'))))
