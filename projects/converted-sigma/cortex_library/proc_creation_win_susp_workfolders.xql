// Title: Execution via WorkFolders.exe
// ID: 0bbc6369-43e3-453d-9944-cae58821c173
// Status: test
// Level: high
// Author: Maxime Thiebaut (@0xThiebaut)
// Date: 2021-10-21
// Tags: attack.stealth, attack.t1218
// Description: Detects using WorkFolders.exe to execute an arbitrary control.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\control.exe" and actor_process_image_path endswith "\\WorkFolders.exe") and not ((action_process_image_path = "C:\\Windows\\System32\\control.exe")))
