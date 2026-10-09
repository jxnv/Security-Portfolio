// Title: SafeBoot Registry Key Deleted Via Reg.EXE
// ID: fc0e89b5-adb0-43c1-b749-c12a10ec37de
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
// Date: 2022-08-08
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " delete " and action_process_image_command_line contains "\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot")) and ((action_process_image_path endswith "reg.exe") or (action_process_image_name = "reg.exe")))
