// Title: Boot Configuration Tampering Via Bcdedit.EXE
// ID: 1444443e-6757-43e4-9ea4-c8fc705f79a2
// Status: stable
// Level: high
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.impact, attack.t1490
// Description: Detects the use of the bcdedit command to tamper with the boot configuration data. This technique is often times used by malware or attackers as a destructive way before launching ransomware.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "bootstatuspolicy" and action_process_image_command_line contains "ignoreallfailures")) or ((action_process_image_command_line contains "recoveryenabled" and action_process_image_command_line contains "no"))) and ((action_process_image_path endswith "\\bcdedit.exe") or (action_process_image_name = "bcdedit.exe")) and (action_process_image_command_line contains "set"))
