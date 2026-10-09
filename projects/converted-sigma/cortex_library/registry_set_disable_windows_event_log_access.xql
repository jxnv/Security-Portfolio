// Title: Windows Event Log Access Tampering Via Registry
// ID: ba226dcf-d390-4642-b9af-b534872f1156
// Status: experimental
// Level: high
// Author: X__Junior
// Date: 2025-01-16
// Tags: attack.privilege-escalation, attack.persistence, attack.defense-impairment, attack.t1547.001, attack.t1112
// Description: Detects changes to the Windows EventLog channel permission values. It focuses on changes to the Security Descriptor Definition Language (SDDL) string, as modifications to these values can restrict access to specific users or groups, potentially aiding in defense evasion by controlling who can view or modify a event log channel. Upon execution, the user shouldn't be able to access the event log channel via the event viewer or via utilities such as "Get-EventLog" or "wevtutil".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\" and TargetObject endswith "\\CustomSD") or ((TargetObject contains "\\Policies\\Microsoft\\Windows\\EventLog\\" or TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels") and TargetObject endswith "\\ChannelAccess")) and ((Details contains "D:(D;") or ((Details contains "D:(" and Details contains ")(D;"))) and not (((action_process_image_path startswith "C:\\Windows\\WinSxS\\" and action_process_image_path endswith "\\TiWorker.exe") or (action_process_image_path = "C:\\Windows\\servicing\\TrustedInstaller.exe"))) and not (((action_process_image_path = "") or (action_process_image_path = null))))
