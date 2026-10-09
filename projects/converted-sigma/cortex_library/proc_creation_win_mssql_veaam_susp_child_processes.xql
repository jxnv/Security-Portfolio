// Title: Suspicious Child Process Of Veeam Dabatase
// ID: d55b793d-f847-4eea-b59a-5ab09908ac90
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\sqlservr.exe" and actor_process_command_line contains "VEEAMSQL") and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wsl.exe" or action_process_image_path endswith "\\wt.exe") and (action_process_image_command_line contains "-ex " or action_process_image_command_line contains "bypass" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "DownloadString" or action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "copy ")) or ((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\netstat.exe" or action_process_image_path endswith "\\nltest.exe" or action_process_image_path endswith "\\ping.exe" or action_process_image_path endswith "\\tasklist.exe" or action_process_image_path endswith "\\whoami.exe"))))
