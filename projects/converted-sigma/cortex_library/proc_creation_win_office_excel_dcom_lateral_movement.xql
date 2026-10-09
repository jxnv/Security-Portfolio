// Title: Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp
// ID: 551d9c1f-816c-445b-a7a6-7a3864720d60
// Status: test
// Level: high
// Author: Aaron Stratton
// Date: 2023-11-13
// Tags: attack.t1021.003, attack.lateral-movement
// Description: Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the "ActivateMicrosoftApp" Excel DCOM object.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_name = "foxprow.exe" or action_process_image_name = "schdplus.exe" or action_process_image_name = "winproj.exe")) or ((action_process_image_path endswith "\\foxprow.exe" or action_process_image_path endswith "\\schdplus.exe" or action_process_image_path endswith "\\winproj.exe"))) and (actor_process_image_path endswith "\\excel.exe"))
