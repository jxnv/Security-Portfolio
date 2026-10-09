// Title: Suspect Svchost Activity
// ID: 16c37b52-b141-42a5-a3ea-bbe098444397
// Status: test
// Level: high
// Author: David Burkett, @signalblur
// Date: 2019-12-28
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line endswith "svchost.exe" and action_process_image_path endswith "\\svchost.exe") and not ((((actor_process_image_path endswith "\\rpcnet.exe" or actor_process_image_path endswith "\\rpcnetp.exe")) or (action_process_image_command_line = null))))
