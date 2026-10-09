// Title: File Download And Execution Via IEExec.EXE
// ID: 9801abb8-e297-4dbf-9fbd-57dde0e830ad
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-05-16
// Tags: attack.command-and-control, attack.t1105
// Description: Detects execution of the IEExec utility to download and execute files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and ((action_process_image_path endswith "\\IEExec.exe") or (action_process_image_name = "IEExec.exe")))
