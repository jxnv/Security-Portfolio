// Title: Suspicious Child Process of Notepad++ Updater - GUP.Exe
// ID: bb0e87ce-c89f-4857-84fa-095e4483e9cb
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-02-03
// Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
// Description: Detects suspicious child process creation by the Notepad++ updater process (gup.exe).
// This could indicate potential exploitation of the updater component to deliver unwanted malware.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\gup.exe") and (((action_process_image_command_line contains "bitsadmin" or action_process_image_command_line contains "certutil" or action_process_image_command_line contains "curl" or action_process_image_command_line contains "finger" or action_process_image_command_line contains "forfiles" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "wget")) or ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\mshta.exe"))))
