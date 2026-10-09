// Title: Stop Windows Service Via Sc.EXE
// ID: 81bcb81b-5b1f-474b-b373-52c871aaa7b1
// Status: test
// Level: low
// Author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-05
// Tags: attack.impact, attack.t1489
// Description: Detects the stopping of a Windows service via the "sc.exe" utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " stop ") and ((action_process_image_name = "sc.exe") or (action_process_image_path endswith "\\sc.exe")))
