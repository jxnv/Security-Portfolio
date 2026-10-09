// Title: Suspicious Control Panel DLL Load
// ID: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2017-04-15
// Tags: attack.stealth, attack.t1218.011
// Description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")) and (actor_process_image_path endswith "\\System32\\control.exe")) and not ((action_process_image_command_line contains "Shell32.dll")))
