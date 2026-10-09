// Title: Remote CHM File Download/Execution Via HH.EXE
// ID: f57c58b3-ee69-4ef5-9041-455bf39aaa89
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-29
// Tags: attack.stealth, attack.t1218.001
// Description: Detects the usage of "hh.exe" to execute/download remotely hosted ".chm" files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://" or action_process_image_command_line contains "\\\\\\\\")) and ((action_process_image_name = "HH.exe") or (action_process_image_path endswith "\\hh.exe")))
