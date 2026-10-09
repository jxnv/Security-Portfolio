// Title: Dllhost.EXE Execution Anomaly
// ID: e7888eb1-13b0-4616-bd99-4bc0c2b054b9
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-27
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects a "dllhost" process spawning with no commandline arguments which is very rare to happen and could indicate process injection activity or malware mimicking similar system processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\dllhost.exe" and (action_process_image_command_line = "dllhost.exe" or action_process_image_command_line = "dllhost")) and not ((action_process_image_command_line = null)))
