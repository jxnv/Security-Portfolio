// Title: Suspicious Workstation Locking via Rundll32
// ID: 3b5b0213-0460-4e3f-8937-3abf98ff7dcc
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-06-04
// Tags: attack.stealth
// Description: Detects a suspicious call to the user32.dll function that locks the user workstation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "user32.dll,") and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")) and (actor_process_image_path endswith "\\cmd.exe") and (action_process_image_command_line contains "LockWorkStation"))
