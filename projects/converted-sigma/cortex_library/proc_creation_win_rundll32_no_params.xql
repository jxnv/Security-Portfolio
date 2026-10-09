// Title: Rundll32 Execution Without CommandLine Parameters
// ID: 1775e15e-b61b-4d14-a1a3-80981298085a
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-05-27
// Tags: attack.stealth, attack.t1202
// Description: Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith "\\rundll32.exe" or action_process_image_command_line endswith "\\rundll32.exe\"" or action_process_image_command_line endswith "\\rundll32")) and not (((actor_process_image_path contains "\\AppData\\Local\\" or actor_process_image_path contains "\\Microsoft\\Edge\\"))))
