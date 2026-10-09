// Title: Suspicious MSDT Parent Process
// ID: 7a74da6b-ea76-47db-92cc-874ad90df734
// Status: test
// Level: high
// Author: Nextron Systems
// Date: 2022-06-01
// Tags: attack.stealth, attack.t1036, attack.t1218
// Description: Detects msdt.exe executed by a suspicious parent as seen in CVE-2022-30190 / Follina exploitation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\msdt.exe") or (action_process_image_name = "msdt.exe")) and ((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\schtasks.exe" or actor_process_image_path endswith "\\wmic.exe" or actor_process_image_path endswith "\\wscript.exe" or actor_process_image_path endswith "\\wsl.exe")))
