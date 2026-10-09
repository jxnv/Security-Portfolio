// Title: Bypass UAC via CMSTP
// ID: e66779cc-383e-4224-a3a4-267eeb585c40
// Status: test
// Level: high
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.privilege-escalation, attack.stealth, attack.t1548.002, attack.t1218.003
// Description: Detect commandline usage of Microsoft Connection Manager Profile Installer (cmstp.exe) to install specially formatted local .INF files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/s" or action_process_image_command_line contains "-s" or action_process_image_command_line contains "/au" or action_process_image_command_line contains "-au" or action_process_image_command_line contains "/ni" or action_process_image_command_line contains "-ni")) and ((action_process_image_path endswith "\\cmstp.exe") or (action_process_image_name = "CMSTP.EXE")))
