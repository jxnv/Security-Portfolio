// Title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
// ID: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-11-26
// Tags: attack.execution
// Description: Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
// Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\wusa.exe") and (((actor_process_image_path contains ":\\Perflogs\\" or actor_process_image_path contains ":\\Users\\Public\\" or actor_process_image_path contains ":\\Windows\\Temp\\" or actor_process_image_path contains "\\Appdata\\Local\\Temp\\" or actor_process_image_path contains "\\Temporary Internet")) or (((actor_process_image_path contains ":\\Users\\" and actor_process_image_path contains "\\Favorites\\")) or ((actor_process_image_path contains ":\\Users\\" and actor_process_image_path contains "\\Favourites\\")) or ((actor_process_image_path contains ":\\Users\\" and actor_process_image_path contains "\\Contacts\\")) or ((actor_process_image_path contains ":\\Users\\" and actor_process_image_path contains "\\Pictures\\")))) and not ((action_process_image_command_line contains ".msu")))
