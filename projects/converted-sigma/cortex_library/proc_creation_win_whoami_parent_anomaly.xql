// Title: Whoami.EXE Execution Anomaly
// ID: 8de1cbe8-d6f5-496d-8237-5f44a721c7a0
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2021-08-12
// Tags: attack.discovery, attack.t1033, car.2016-03-001
// Description: Detects the execution of whoami.exe with suspicious parent processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\whoami.exe") or (action_process_image_name = "whoami.exe")) and not ((((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\powershell_ise.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe")) or ((actor_process_image_path = "" or actor_process_image_path = "-")) or (actor_process_image_path = null))) and not ((actor_process_image_path endswith ":\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe")))
