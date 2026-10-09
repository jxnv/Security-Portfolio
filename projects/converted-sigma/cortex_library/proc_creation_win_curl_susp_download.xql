// Title: Suspicious Curl.EXE Download
// ID: e218595b-bbe7-4ee5-8a96-f32a24ad3468
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-07-03
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\curl.exe") or (Product = "The curl executable")) and (((action_process_image_command_line endswith ".dll" or action_process_image_command_line endswith ".gif" or action_process_image_command_line endswith ".jpeg" or action_process_image_command_line endswith ".jpg" or action_process_image_command_line endswith ".png" or action_process_image_command_line endswith ".temp" or action_process_image_command_line endswith ".tmp" or action_process_image_command_line endswith ".txt" or action_process_image_command_line endswith ".vbe" or action_process_image_command_line endswith ".vbs")) or ((action_process_image_command_line contains "%AppData%" or action_process_image_command_line contains "%Public%" or action_process_image_command_line contains "%Temp%" or action_process_image_command_line contains "%tmp%" or action_process_image_command_line contains "\\AppData\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Temp\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "C:\\PerfLogs\\" or action_process_image_command_line contains "C:\\ProgramData\\" or action_process_image_command_line contains "C:\\Windows\\Temp\\"))) and not ((actor_process_image_path = "C:\\Program Files\\Git\\usr\\bin\\sh.exe" and action_process_image_path = "C:\\Program Files\\Git\\mingw64\\bin\\curl.exe" and (action_process_image_command_line contains "--silent --show-error --output " and action_process_image_command_line contains "gfw-httpget-" and action_process_image_command_line contains "AppData"))))
