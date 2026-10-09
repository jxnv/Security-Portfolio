// Title: Mstsc.EXE Execution With Local RDP File
// ID: 5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems), Christopher Peacock @securepeacock
// Date: 2023-04-18
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects potential RDP connection via Mstsc using a local ".rdp" file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line endswith ".rdp" or action_process_image_command_line endswith ".rdp\"")) and ((action_process_image_path endswith "\\mstsc.exe") or (action_process_image_name = "mstsc.exe"))) and not ((actor_process_image_path = "C:\\Windows\\System32\\lxss\\wslhost.exe" and action_process_image_command_line contains "C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp")))
