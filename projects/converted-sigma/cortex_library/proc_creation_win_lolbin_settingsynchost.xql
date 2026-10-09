// Title: Using SettingSyncHost.exe as LOLBin
// ID: b2ddd389-f676-4ac4-845a-e00781a48e5f
// Status: test
// Level: high
// Author: Anton Kutepov, oscd.community
// Date: 2020-02-05
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.008
// Description: Detects using SettingSyncHost.exe to run hijacked binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\"))) and ((actor_process_command_line contains "cmd.exe /c" and actor_process_command_line contains "RoamDiag.cmd" and actor_process_command_line contains "-outputpath")))
