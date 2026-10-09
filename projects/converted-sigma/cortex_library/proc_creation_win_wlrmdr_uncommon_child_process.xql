// Title: Wlrmdr.EXE Uncommon Argument Or Child Process
// ID: 9cfc00b6-bfb7-49ce-9781-ef78503154bb
// Status: experimental
// Level: medium
// Author: frack113, manasmbellani
// Date: 2022-02-16
// Tags: attack.stealth, attack.t1218
// Description: Detects the execution of "Wlrmdr.exe" with the "-u" command line flag which allows anything passed to it to be an argument of the ShellExecute API, which would allow an attacker to execute arbitrary binaries.
// This detection also focuses on any uncommon child processes spawned from "Wlrmdr.exe" as a supplement for those that posses "ParentImage" telemetry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\wlrmdr.exe") or ((((action_process_image_command_line contains "-a " or action_process_image_command_line contains "/a ")) and ((action_process_image_command_line contains "-f " or action_process_image_command_line contains "/f ")) and ((action_process_image_command_line contains "-m " or action_process_image_command_line contains "/m ")) and ((action_process_image_command_line contains "-s " or action_process_image_command_line contains "/s ")) and ((action_process_image_command_line contains "-t " or action_process_image_command_line contains "/t ")) and ((action_process_image_command_line contains "-u " or action_process_image_command_line contains "/u ")) and ((action_process_image_path endswith "\\wlrmdr.exe") or (action_process_image_name = "WLRMNDR.EXE"))) and not ((((actor_process_image_path = "" or actor_process_image_path = "-")) or (actor_process_image_path = null) or (actor_process_image_path = "C:\\Windows\\System32\\winlogon.exe")))))
