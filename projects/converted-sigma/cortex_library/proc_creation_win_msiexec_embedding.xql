// Title: Suspicious MsiExec Embedding Parent
// ID: 4a2a2c3e-209f-4d01-b513-4155a540b469
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-04-16
// Tags: attack.stealth, attack.t1218.007
// Description: Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cmd.exe") and (actor_process_command_line contains "MsiExec.exe" and actor_process_command_line contains "-Embedding ")) and not (((action_process_image_path endswith ":\\Windows\\System32\\cmd.exe" and action_process_image_command_line contains "C:\\Program Files\\SplunkUniversalForwarder\\bin\\") or ((action_process_image_command_line contains "\\DismFoDInstall.cmd") or ((actor_process_command_line contains "\\MsiExec.exe -Embedding " and actor_process_command_line contains "Global\\MSI0000"))))))
