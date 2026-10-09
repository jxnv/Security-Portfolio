// Title: Delete Important Scheduled Task
// ID: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.impact, attack.t1489
// Description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/delete" or action_process_image_command_line contains "-delete")) and ((action_process_image_command_line contains "\\Windows\\BitLocker" or action_process_image_command_line contains "\\Windows\\ExploitGuard" or action_process_image_command_line contains "\\Windows\\SystemRestore\\SR" or action_process_image_command_line contains "\\Windows\\UpdateOrchestrator\\" or action_process_image_command_line contains "\\Windows\\Windows Defender\\" or action_process_image_command_line contains "\\Windows\\WindowsBackup\\" or action_process_image_command_line contains "\\Windows\\WindowsUpdate\\")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
