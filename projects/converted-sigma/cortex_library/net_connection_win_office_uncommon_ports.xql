// Title: Office Application Initiated Network Connection Over Uncommon Ports
// ID: 3b5ba899-9842-4bc2-acc2-12308498bf42
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-12
// Tags: attack.command-and-control, attack.stealth
// Description: Detects an office suit application (Word, Excel, PowerPoint, Outlook) communicating to target systems over uncommon ports.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and (action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe" or action_process_image_path endswith "\\wordview.exe")) and not ((((action_remote_port = 53 or action_remote_port = 80 or action_remote_port = 139 or action_remote_port = 389 or action_remote_port = 443 or action_remote_port = 445 or action_remote_port = 3268)) or (action_process_image_path contains ":\\Program Files\\Microsoft Office\\" and action_process_image_path endswith "\\OUTLOOK.EXE" and (action_remote_port = 143 or action_remote_port = 465 or action_remote_port = 587 or action_remote_port = 993 or action_remote_port = 995)))))
