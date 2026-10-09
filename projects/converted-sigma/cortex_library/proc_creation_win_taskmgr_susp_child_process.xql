// Title: New Process Created Via Taskmgr.EXE
// ID: 3d7679bd-0c00-440c-97b0-3f204273e6c7
// Status: test
// Level: low
// Author: Florian Roth (Nextron Systems)
// Date: 2018-03-13
// Tags: attack.stealth, attack.t1036
// Description: Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\taskmgr.exe") and not (((action_process_image_path endswith ":\\Windows\\System32\\mmc.exe" or action_process_image_path endswith ":\\Windows\\System32\\resmon.exe" or action_process_image_path endswith ":\\Windows\\System32\\Taskmgr.exe"))))
