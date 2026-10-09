// Title: Suspicious HH.EXE Execution
// ID: e8a95b5e-c891-46e2-b33a-93937d3abc31
// Status: test
// Level: high
// Author: Maxim Pavlunin
// Date: 2020-04-01
// Tags: attack.execution, attack.initial-access, attack.stealth, attack.t1047, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.007, attack.t1218, attack.t1218.001, attack.t1218.010, attack.t1218.011, attack.t1566, attack.t1566.001
// Description: Detects a suspicious execution of a Microsoft HTML Help (HH.exe)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "HH.exe") or (action_process_image_path endswith "\\hh.exe")) and ((action_process_image_command_line contains ".application" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\Content.Outlook\\" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Windows\\Temp\\")))
