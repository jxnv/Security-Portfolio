// Title: Suspicious Usage of For Loop with Recursive Directory Search in CMD
// ID: 2782fbd8-b662-4eb5-9962-5bfbfb671e7b
// Status: experimental
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2025-11-12
// Tags: attack.execution, attack.stealth, attack.t1059.003, attack.t1027.010
// Description: Detects suspicious usage of the cmd.exe 'for /f' loop combined with the 'tokens=' parameter and a recursive directory listing.
// This pattern may indicate an attempt to discover and execute system binaries dynamically, for example powershell, a technique sometimes used by attackers to evade detection.
// This behavior has been observed in various malicious lnk files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "for /f" and action_process_image_command_line contains "tokens=" and action_process_image_command_line contains "in (" and action_process_image_command_line contains "dir")) or ((actor_process_command_line contains "for /f" and actor_process_command_line contains "tokens=" and actor_process_command_line contains "in (" and actor_process_command_line contains "dir")))
