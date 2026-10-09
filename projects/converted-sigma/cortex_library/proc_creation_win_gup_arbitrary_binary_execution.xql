// Title: Arbitrary Binary Execution Using GUP Utility
// ID: d65aee4d-2292-4cea-b832-83accd6cfa43
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-10
// Tags: attack.execution
// Description: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\gup.exe" and action_process_image_path endswith "\\explorer.exe") and not (((action_process_image_path endswith "\\explorer.exe" and action_process_image_command_line contains "\\Notepad++\\notepad++.exe") or (action_process_image_command_line = null) or (actor_process_image_path contains "\\Notepad++\\updater\\"))))
