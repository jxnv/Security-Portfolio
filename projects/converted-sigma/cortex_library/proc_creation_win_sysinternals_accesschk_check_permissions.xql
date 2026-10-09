// Title: Permission Check Via Accesschk.EXE
// ID: c625d754-6a3d-4f65-9c9a-536aea960d37
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov (idea), Mangatas Tondang, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-10-13
// Tags: attack.discovery, attack.t1069.001
// Description: Detects the usage of the "Accesschk" utility, an access and privilege audit tool developed by SysInternal and often being abused by attacker to verify process privileges
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "uwcqv " or action_process_image_command_line contains "kwsu " or action_process_image_command_line contains "qwsu " or action_process_image_command_line contains "uwdqs ")) and ((Product endswith "AccessChk") or (Description contains "Reports effective permissions") or ((action_process_image_path endswith "\\accesschk.exe" or action_process_image_path endswith "\\accesschk64.exe" or action_process_image_path endswith "\\accesschk64a.exe")) or (action_process_image_name = "accesschk.exe")))
