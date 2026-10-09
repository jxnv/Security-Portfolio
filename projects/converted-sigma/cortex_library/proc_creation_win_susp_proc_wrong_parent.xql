// Title: Windows Processes Suspicious Parent Directory
// ID: 96036718-71cc-4027-a538-d1587e0006a7
// Status: test
// Level: low
// Author: vburov
// Date: 2019-02-23
// Tags: attack.stealth, attack.t1036.003, attack.t1036.005
// Description: Detect suspicious parent processes of well-known Windows processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\svchost.exe" or action_process_image_path endswith "\\taskhost.exe" or action_process_image_path endswith "\\lsm.exe" or action_process_image_path endswith "\\lsass.exe" or action_process_image_path endswith "\\services.exe" or action_process_image_path endswith "\\lsaiso.exe" or action_process_image_path endswith "\\csrss.exe" or action_process_image_path endswith "\\wininit.exe" or action_process_image_path endswith "\\winlogon.exe")) and not ((((actor_process_image_path contains "\\Windows Defender\\" or actor_process_image_path contains "\\Microsoft Security Client\\") and actor_process_image_path endswith "\\MsMpEng.exe") or ((actor_process_image_path = null) or ((actor_process_image_path = "" or actor_process_image_path = "-"))) or (((actor_process_image_path endswith "\\SavService.exe" or actor_process_image_path endswith "\\ngen.exe")) or ((actor_process_image_path contains "\\System32\\" or actor_process_image_path contains "\\SysWOW64\\"))))))
