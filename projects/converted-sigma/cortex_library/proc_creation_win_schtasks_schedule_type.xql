// Title: Suspicious Schtasks Schedule Types
// ID: 24c8392b-aa3c-46b7-a545-43f71657fe98
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations or modification on a suspicious schedule type
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")) and ((action_process_image_command_line contains " ONLOGON " or action_process_image_command_line contains " ONSTART " or action_process_image_command_line contains " ONCE " or action_process_image_command_line contains " ONIDLE "))) and not (((action_process_image_command_line contains "NT AUT" or action_process_image_command_line contains " SYSTEM" or action_process_image_command_line contains "HIGHEST"))))
