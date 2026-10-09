// Title: Disable Windows Defender Functionalities Via Registry Keys
// ID: 0eb46774-f1ab-4a74-8238-1155855f2263
// Status: test
// Level: high
// Author: AlertIQ, Ján Trenčanský, frack113, Nasreddine Bencherchali, Swachchhanda Shrawan Poudel
// Date: 2022-08-01
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects when attackers or tools disable Windows Defender functionalities via the Windows registry
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\SOFTWARE\\Microsoft\\Windows Defender\\" or TargetObject contains "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\" or TargetObject contains "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\")) and (((TargetObject endswith "\\DisallowExploitProtectionOverride" or TargetObject endswith "\\Features\\TamperProtection" or TargetObject endswith "\\MpEngine\\MpEnablePus" or TargetObject endswith "\\PUAProtection" or TargetObject endswith "\\Signature Update\\ForceUpdateFromMU" or TargetObject endswith "\\SpyNet\\SpynetReporting" or TargetObject endswith "\\SpyNet\\SubmitSamplesConsent" or TargetObject endswith "\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess") and Details = "DWORD (0x00000000)") or ((TargetObject endswith "\\DisableAntiSpyware" or TargetObject endswith "\\DisableAntiVirus" or TargetObject endswith "\\DisableBehaviorMonitoring" or TargetObject endswith "\\DisableBlockAtFirstSeen" or TargetObject endswith "\\DisableEnhancedNotifications" or TargetObject endswith "\\DisableIntrusionPreventionSystem" or TargetObject endswith "\\DisableIOAVProtection" or TargetObject endswith "\\DisableOnAccessProtection" or TargetObject endswith "\\DisableRealtimeMonitoring" or TargetObject endswith "\\DisableScanOnRealtimeEnable" or TargetObject endswith "\\DisableScriptScanning") and Details = "DWORD (0x00000001)")) and not ((action_process_image_path startswith "C:\\Program Files\\Symantec\\Symantec Endpoint Protection\\" and action_process_image_path endswith "\\sepWscSvc64.exe")))
