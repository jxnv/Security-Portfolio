// Title: Potentially Suspicious Child Processes Spawned by ConHost
// ID: dfa03a09-8b92-4d83-8e74-f72839b1c407
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-02-05
// Tags: attack.stealth, attack.t1202, attack.t1218
// Description: Detects suspicious child processes related to Windows Shell utilities spawned by `conhost.exe`, which could indicate malicious activity using trusted system components.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "cmd.exe" or action_process_image_name = "cscript.exe" or action_process_image_name = "mshta.exe" or action_process_image_name = "powershell_ise.exe" or action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll" or action_process_image_name = "regsvr32.exe" or action_process_image_name = "wscript.exe"))) and (actor_process_image_path endswith "\\conhost.exe"))
