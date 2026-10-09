// Title: Suspicious Chromium Browser Instance Executed With Custom Extension
// ID: 27ba3207-dd30-4812-abbf-5d20c57d474e
// Status: test
// Level: high
// Author: Aedan Russell, frack113, X__Junior (Nextron Systems)
// Date: 2022-06-19
// Tags: attack.persistence, attack.t1176.001
// Description: Detects a suspicious process spawning a Chromium based browser process with the 'load-extension' flag to start an instance with a custom extension
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\wscript.exe") and (action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\vivaldi.exe") and action_process_image_command_line contains "--load-extension=")
