// Title: File Download Using Notepad++ GUP Utility
// ID: 44143844-0631-49ab-97a0-96387d6b2d7c
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-10
// Tags: attack.command-and-control, attack.t1105
// Description: Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " -unzipTo " and action_process_image_command_line contains "http")) and ((action_process_image_path endswith "\\GUP.exe") or (action_process_image_name = "gup.exe"))) and not ((actor_process_image_path endswith "\\notepad++.exe")))
