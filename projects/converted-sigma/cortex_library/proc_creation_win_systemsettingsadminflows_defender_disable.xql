// Title: Windows Defender Disabled Via SystemSettingsAdminFlows.EXE
// ID: da92713f-ca2d-4fab-8320-098013d3f43a
// Status: experimental
// Level: high
// Author: Chirag Damani (KPMG India), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-07-01
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the usage of SystemSettingsAdminFlows.exe to disable Windows Defender.
// SystemSettingsAdminFlows.exe is a legitimate Windows component used for administrative configuration tasks.
// However, attackers may abuse it to disable Windows Defender as part of their attack chain, especially in the context of ransomware or other malware campaigns.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "defender") and ((action_process_image_path endswith "\\SystemSettingsAdminFlows.exe") or (action_process_image_name = "SystemSettingsAdminFlows.EXE"))) and ((((action_process_image_command_line contains "RTP " or action_process_image_command_line contains "RealTimeProtection " or action_process_image_command_line contains "DisableEnhancedNotifications ")) and (action_process_image_command_line contains "1")) or (((action_process_image_command_line contains "SubmitSamplesConsent " or action_process_image_command_line contains "SpyNetReporting " or action_process_image_command_line contains "DisableCDPUserAuthPolicy ")) and (action_process_image_command_line contains "0"))))
