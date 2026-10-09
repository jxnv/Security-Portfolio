// Title: Suspicious ArcSOC.exe Child Process
// ID: 8e95e73e-ba02-4a87-b4d7-0929b8053038
// Status: experimental
// Level: high
// Author: Micah Babinski
// Date: 2025-11-25
// Tags: attack.execution, attack.t1059, attack.t1203
// Description: Detects script interpreters, command-line tools, and similar suspicious child processes of ArcSOC.exe.
// ArcSOC.exe is the process name which hosts ArcGIS Server REST services. If an attacker compromises an ArcGIS
// Server system and uploads a malicious Server Object Extension (SOE), they can send crafted requests to the corresponding
// service endpoint and remotely execute code from the ArcSOC.exe process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\ArcSOC.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe")) and not ((action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line = "cmd.exe /c \"ver\"")))
