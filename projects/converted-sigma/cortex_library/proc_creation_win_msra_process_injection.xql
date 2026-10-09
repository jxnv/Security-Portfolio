// Title: Potential Process Injection Via Msra.EXE
// ID: 744a188b-0415-4792-896f-11ddb0588dbc
// Status: test
// Level: high
// Author: Alexander McDonald
// Date: 2022-06-24
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\msra.exe" and actor_process_command_line endswith "msra.exe" and (action_process_image_path endswith "\\arp.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\netstat.exe" or action_process_image_path endswith "\\nslookup.exe" or action_process_image_path endswith "\\route.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\whoami.exe"))
