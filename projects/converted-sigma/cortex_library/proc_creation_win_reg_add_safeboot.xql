// Title: Add SafeBoot Keys Via Reg Utility
// ID: d7662ff6-9e97-4596-a61d-9839e32dee8d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-02
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects execution of "reg.exe" commands with the "add" or "copy" flags on safe boot registry keys. Often used by attacker to allow the ransomware to work in safe mode as some security products do not
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " copy " or action_process_image_command_line contains " add ")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")) and (action_process_image_command_line contains "\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot"))
