// Title: Process Memory Dump Via Comsvcs.DLL
// ID: 646ea171-dded-4578-8a4d-65e9822892e3
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2020-02-18
// Tags: attack.credential-access, attack.stealth, attack.t1036, attack.t1003.001, car.2013-05-009
// Description: Detects a process memory dump via "comsvcs.dll" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE") or (action_process_image_command_line contains "rundll32")) and ((action_process_image_command_line contains "comsvcs" and action_process_image_command_line contains "full") and (action_process_image_command_line contains "#-" or action_process_image_command_line contains "#+" or action_process_image_command_line contains "#24" or action_process_image_command_line contains "24 " or action_process_image_command_line contains "MiniDump" or action_process_image_command_line contains "#65560"))) or ((action_process_image_command_line contains "24" and action_process_image_command_line contains "comsvcs" and action_process_image_command_line contains "full") and (action_process_image_command_line contains " #" or action_process_image_command_line contains ",#" or action_process_image_command_line contains ", #" or action_process_image_command_line contains "\"#")))
