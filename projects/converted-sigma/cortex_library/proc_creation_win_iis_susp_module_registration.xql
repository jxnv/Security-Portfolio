// Title: Suspicious IIS Module Registration
// ID: 043c4b8b-3a54-4780-9682-081cb6b8185c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Microsoft (idea)
// Date: 2022-08-04
// Tags: attack.persistence, attack.t1505.004
// Description: Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\w3wp.exe") and ((action_process_image_command_line contains "appcmd.exe add module") or (action_process_image_command_line contains " system.enterpriseservices.internal.publish" and action_process_image_path endswith "\\powershell.exe") or ((action_process_image_command_line contains "gacutil" and action_process_image_command_line contains " /I"))))
