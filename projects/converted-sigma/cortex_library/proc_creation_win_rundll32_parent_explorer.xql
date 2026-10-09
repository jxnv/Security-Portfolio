// Title: Rundll32 Spawned Via Explorer.EXE
// ID: 1723e720-616d-4ddc-ab02-f7e3685a4713
// Status: test
// Level: medium
// Author: CD_ROM_
// Date: 2022-05-21
// Tags: attack.stealth
// Description: Detects execution of "rundll32.exe" with a parent process of Explorer.exe. This has been observed by variants of Raspberry Robin, as first reported by Red Canary.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")) and (actor_process_image_path endswith "\\explorer.exe")) and not (((action_process_image_command_line contains " C:\\Windows\\System32\\") or (action_process_image_command_line endswith " -localserver 22d8c27b-47a1-48d1-ad08-7da7abd79617"))))
