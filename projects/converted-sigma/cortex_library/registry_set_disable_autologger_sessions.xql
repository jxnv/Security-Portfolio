// Title: Potential AutoLogger Sessions Tampering
// ID: f37b4bce-49d0-4087-9f5b-58bffda77316
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging.
// The AutoLogger event tracing session records events up that occur early in the operating system boot process.
// Applications and device drivers can use the AutoLogger session to capture traces before the user logs in, and also used by security solutions as telemetry source.
// Adversaries may disable these sessions to evade detection and prevent security monitoring of early boot activities and system events.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Control\\WMI\\Autologger\\") and ((TargetObject contains "\\EventLog-" or TargetObject contains "\\Defender") and (TargetObject endswith "\\Enabled" or TargetObject endswith "\\Start") and Details = "DWORD (0x00000000)")) and not ((((action_process_image_path startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or action_process_image_path startswith "C:\\Program Files\\Windows Defender\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Windows Defender\\") and action_process_image_path endswith "\\MsMpEng.exe" and (TargetObject contains "\\DefenderApiLogger\\" or TargetObject contains "\\DefenderAuditLogger\\")) or (action_process_image_path = "C:\\Windows\\system32\\wevtutil.exe"))))
