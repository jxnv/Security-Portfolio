// Title: Sdiagnhost Calling Suspicious Child Process
// ID: f3d39c45-de1a-4486-a687-ab126124f744
// Status: test
// Level: high
// Author: Nextron Systems, @Kostastsale
// Date: 2022-06-01
// Tags: attack.stealth, attack.t1036, attack.t1218
// Description: Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\sdiagnhost.exe" and (action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\taskkill.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\calc.exe")) and not (((action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line contains "bits") or (action_process_image_path endswith "\\powershell.exe" and (action_process_image_command_line endswith "-noprofile -" or action_process_image_command_line endswith "-noprofile")))))
