// Title: Terminal Service Process Spawn
// ID: 1012f107-b8f1-4271-af30-5aed2de89b39
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-05-22
// Tags: attack.initial-access, attack.t1190, attack.lateral-movement, attack.t1210, car.2013-07-002
// Description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line contains "\\svchost.exe" and actor_process_command_line contains "termsvcs")) and not ((((action_process_image_path endswith "\\rdpclip.exe" or action_process_image_path endswith ":\\Windows\\System32\\csrss.exe" or action_process_image_path endswith ":\\Windows\\System32\\wininit.exe" or action_process_image_path endswith ":\\Windows\\System32\\winlogon.exe")) or (action_process_image_path = null))))
