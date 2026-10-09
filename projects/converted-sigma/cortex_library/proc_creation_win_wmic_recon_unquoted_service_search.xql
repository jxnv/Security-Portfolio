// Title: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
// ID: 68bcd73b-37ef-49cb-95fc-edc809730be6
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.execution, attack.t1047
// Description: Detects known WMI recon method to look for unquoted service paths using wmic. Often used by pentester and attacker enumeration scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " service get " and action_process_image_command_line contains "name,displayname,pathname,startmode")) and ((action_process_image_name = "wmic.exe") or (action_process_image_path endswith "\\WMIC.exe")))
