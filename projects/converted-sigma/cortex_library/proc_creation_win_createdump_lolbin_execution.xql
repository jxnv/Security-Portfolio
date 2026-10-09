// Title: CreateDump Process Dump
// ID: 515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-04
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects uses of the createdump.exe LOLOBIN utility to dump process memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -u " or action_process_image_command_line contains " --full " or action_process_image_command_line contains " -f " or action_process_image_command_line contains " --name " or action_process_image_command_line contains ".dmp ")) and ((action_process_image_path endswith "\\createdump.exe") or (action_process_image_name = "FX_VER_INTERNALNAME_STR")))
