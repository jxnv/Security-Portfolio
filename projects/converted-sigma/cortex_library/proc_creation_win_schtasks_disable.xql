// Title: Disable Important Scheduled Task
// ID: 9ac94dc8-9042-493c-ba45-3b5e7c86b980
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems), X__Junior
// Date: 2021-12-26
// Tags: attack.impact, attack.t1489
// Description: Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/disable" or action_process_image_command_line contains "-disable")) and ((action_process_image_command_line contains "\\Windows\\BitLocker" or action_process_image_command_line contains "\\Windows\\ExploitGuard" or action_process_image_command_line contains "\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh" or action_process_image_command_line contains "\\Windows\\SystemRestore\\SR" or action_process_image_command_line contains "\\Windows\\UpdateOrchestrator\\" or action_process_image_command_line contains "\\Windows\\Windows Defender\\" or action_process_image_command_line contains "\\Windows\\WindowsBackup\\" or action_process_image_command_line contains "\\Windows\\WindowsUpdate\\")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
