// Title: Suspicious Userinit Child Process
// ID: b655a06a-31c0-477a-95c2-3726b83d649d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Samir Bousseaden (idea)
// Date: 2019-06-17
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects a suspicious child process of userinit
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\userinit.exe") and not ((((action_process_image_path endswith "\\explorer.exe") or (action_process_image_name = "explorer.exe") or (action_process_image_command_line = "C:\\Windows\\Explorer.EXE")) or (action_process_image_command_line contains "\\netlogon\\") or (action_process_image_path = null))))
