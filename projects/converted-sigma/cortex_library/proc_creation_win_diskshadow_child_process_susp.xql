// Title: Potentially Suspicious Child Process Of DiskShadow.EXE
// ID: 9f546b25-5f12-4c8d-8532-5893dcb1e4b8
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-15
// Tags: attack.stealth, attack.t1218
// Description: Detects potentially suspicious child processes of "Diskshadow.exe". This could be an attempt to bypass parent/child relationship detection or application whitelisting rules.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\diskshadow.exe" and (action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe"))
