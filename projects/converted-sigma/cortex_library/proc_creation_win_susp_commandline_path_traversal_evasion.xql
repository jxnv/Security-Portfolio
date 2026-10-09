// Title: Potential Command Line Path Traversal Evasion Attempt
// ID: 1327381e-6ab0-4f38-b583-4c1b8346a56b
// Status: test
// Level: medium
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-10-26
// Tags: attack.stealth, attack.t1036
// Description: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path contains "\\Windows\\" and (action_process_image_command_line contains "\\..\\Windows\\" or action_process_image_command_line contains "\\..\\System32\\" or action_process_image_command_line contains "\\..\\..\\")) or (action_process_image_command_line contains ".exe\\..\\")) and not (((action_process_image_command_line contains "\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\..\\") or (action_process_image_command_line contains "\\Google\\Drive\\googledrivesync.exe\\..\\"))))
