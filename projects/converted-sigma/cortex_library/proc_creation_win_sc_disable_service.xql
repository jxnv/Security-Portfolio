// Title: Service StartupType Change Via Sc.EXE
// ID: 85c312b7-f44d-4a51-a024-d671c40b49fc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.execution, attack.defense-impairment, attack.t1685
// Description: Detect the use of "sc.exe" to change the startup type of a service to "disabled" or "demand"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " config " and action_process_image_command_line contains "start") and (action_process_image_command_line contains "disabled" or action_process_image_command_line contains "demand")) and ((action_process_image_path endswith "\\sc.exe") or (action_process_image_name = "sc.exe")))
