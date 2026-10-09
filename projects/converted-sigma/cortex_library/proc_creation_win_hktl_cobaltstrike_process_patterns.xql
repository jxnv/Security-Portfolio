// Title: Potential CobaltStrike Process Patterns
// ID: f35c5d71-b489-4e22-a115-f003df287317
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-07-27
// Tags: attack.execution, attack.t1059
// Description: Detects potential process patterns related to Cobalt Strike beacon activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_command_line contains "cmd.exe /C echo" and actor_process_command_line contains " > \\\\\\\\.\\\\pipe") and action_process_image_command_line endswith "conhost.exe 0xffffffff -ForceV1") or (actor_process_command_line endswith "/C whoami" and action_process_image_command_line endswith "conhost.exe 0xffffffff -ForceV1") or (action_process_image_command_line endswith "cmd.exe /C whoami" and actor_process_image_path startswith "C:\\Temp\\") or ((actor_process_image_path endswith "\\runonce.exe" or actor_process_image_path endswith "\\dllhost.exe") and (action_process_image_command_line contains "cmd.exe /c echo" and action_process_image_command_line contains "> \\\\\\\\.\\\\pipe")))
