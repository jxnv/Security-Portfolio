// Title: Renamed CreateDump Utility Execution
// ID: 1a1ed54a-2ba4-4221-94d5-01dee560d71e
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-20
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_command_line contains " -u " and action_process_image_command_line contains " -f " and action_process_image_command_line contains ".dmp")) or ((action_process_image_command_line contains " --full " and action_process_image_command_line contains " --name " and action_process_image_command_line contains ".dmp"))) or (action_process_image_name = "FX_VER_INTERNALNAME_STR")) and not ((action_process_image_path endswith "\\createdump.exe")))
