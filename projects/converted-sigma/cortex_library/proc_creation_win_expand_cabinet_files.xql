// Title: Potentially Suspicious Cabinet File Expansion
// ID: 9f107a84-532c-41af-b005-8d12a607639f
// Status: test
// Level: medium
// Author: Bhabesh Raj, X__Junior (Nextron Systems)
// Date: 2021-07-30
// Tags: attack.stealth, attack.t1218
// Description: Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\expand.exe" and (action_process_image_command_line contains "-F:" or action_process_image_command_line contains "/F:")) and (((action_process_image_command_line contains ":\\Perflogs\\" or action_process_image_command_line contains ":\\ProgramData" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\Admin$\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\AppData\\Roaming\\" or action_process_image_command_line contains "\\C$\\" or action_process_image_command_line contains "\\Temporary Internet")) or (((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Favorites\\")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Favourites\\")) or ((action_process_image_command_line contains ":\\Users\\" and action_process_image_command_line contains "\\Contacts\\")))) and not ((actor_process_image_path = "C:\\Program Files (x86)\\Dell\\UpdateService\\ServiceShell.exe" and action_process_image_command_line contains "C:\\ProgramData\\Dell\\UpdateService\\Temp\\")))
