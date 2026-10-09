// Title: HackTool - SharPersist Execution
// ID: 26488ad0-f9fd-4536-876f-52fea846a2e4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053
// Description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -t schtask -c " or action_process_image_command_line contains " -t startupfolder -c ")) or ((action_process_image_command_line contains " -t reg -c " and action_process_image_command_line contains " -m add")) or ((action_process_image_command_line contains " -t service -c " and action_process_image_command_line contains " -m add")) or ((action_process_image_command_line contains " -t schtask -c " and action_process_image_command_line contains " -m add")) or ((action_process_image_path endswith "\\SharPersist.exe") or (Product = "SharPersist")))
