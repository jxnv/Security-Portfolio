// Title: Disable Windows Event Logging Via Registry
// ID: 2f78da12-f7c7-430b-8b19-a28f269b77a3
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-04
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects tampering with the "Enabled" registry key in order to disable Windows logging of a Windows event channel
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\" and TargetObject endswith "\\Enabled" and Details = "DWORD (0x00000000)") and not (((action_process_image_path startswith "C:\\Windows\\winsxs\\" and action_process_image_path endswith "\\TiWorker.exe") or (action_process_image_path = "C:\\Windows\\System32\\svchost.exe" and (TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-FileInfoMinifilter" or TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-ASN1\\" or TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-AppCompat\\" or TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Runtime\\Error\\" or TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-CAPI2/Operational\\")) or (action_process_image_path = "C:\\Windows\\servicing\\TrustedInstaller.exe" and TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Compat-Appraiser") or (action_process_image_path = "C:\\Windows\\system32\\wevtutil.exe"))) and not (((action_process_image_path = "") or (action_process_image_path = null))))
