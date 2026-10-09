// Title: Service Startup Type Change Via Wmic.EXE
// ID: c0514f28-fdae-42df-b886-06e2b2bc5b37
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-04-27
// Tags: attack.execution, attack.defense-impairment, attack.t1047, attack.t1685
// Description: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " service " and action_process_image_command_line contains "ChangeStartMode") and (action_process_image_command_line contains "Manual" or action_process_image_command_line contains "Disabled")) and ((action_process_image_path endswith "\\WMIC.exe") or (action_process_image_name = "wmic.exe")))
