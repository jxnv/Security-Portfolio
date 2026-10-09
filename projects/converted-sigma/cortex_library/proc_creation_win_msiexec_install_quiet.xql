// Title: Msiexec Quiet Installation
// ID: 79a87aa6-e4bd-42fc-a5bb-5e6fbdcd62f5
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-16
// Tags: attack.stealth, attack.t1218.007
// Description: Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
// Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "-i" or action_process_image_command_line contains "/i" or action_process_image_command_line contains "-package" or action_process_image_command_line contains "/package" or action_process_image_command_line contains "-a" or action_process_image_command_line contains "/a" or action_process_image_command_line contains "-j" or action_process_image_command_line contains "/j")) and ((action_process_image_path endswith "\\msiexec.exe") or (action_process_image_name = "msiexec.exe")) and ((action_process_image_command_line contains "-q" or action_process_image_command_line contains "/q"))) and not (((actor_process_image_path = "C:\\Windows\\CCM\\Ccm32BitLauncher.exe" and (IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384")) or (actor_process_image_path startswith "C:\\Windows\\Temp\\"))) and not (((actor_process_image_path startswith "C:\\Users\\" and actor_process_image_path contains "\\AppData\\Local\\Temp\\") or (actor_process_image_path endswith "C:\\Windows\\System32\\wsl.exe" and action_process_image_path endswith "C:\\Windows\\System32\\msiexec.exe"))))
