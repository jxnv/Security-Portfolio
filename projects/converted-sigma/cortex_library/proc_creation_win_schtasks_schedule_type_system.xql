// Title: Suspicious Schtasks Schedule Type With High Privileges
// ID: 7a02e22e-b885-4404-b38b-1ddc7e65258a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-31
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")) and ((action_process_image_command_line contains "NT AUT" or action_process_image_command_line contains " SYSTEM" or action_process_image_command_line contains "HIGHEST")) and ((action_process_image_command_line contains " ONLOGON " or action_process_image_command_line contains " ONSTART " or action_process_image_command_line contains " ONCE " or action_process_image_command_line contains " ONIDLE ")))
