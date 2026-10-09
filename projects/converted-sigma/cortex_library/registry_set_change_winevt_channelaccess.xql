// Title: Change Winevt Channel Access Permission Via Registry
// ID: 7d9263bd-dc47-4a58-bc92-5474abab390c
// Status: test
// Level: high
// Author: frack113
// Date: 2022-09-17
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects tampering with the "ChannelAccess" registry key in order to change access to Windows event channel.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\" and TargetObject endswith "\\ChannelAccess" and (Details contains "(A;;0x1;;;LA)" or Details contains "(A;;0x1;;;SY)" or Details contains "(A;;0x5;;;BA)")) and not (((action_process_image_path startswith "C:\\Windows\\WinSxS\\" and action_process_image_path endswith "\\TiWorker.exe") or (action_process_image_path = "C:\\Windows\\servicing\\TrustedInstaller.exe"))))
