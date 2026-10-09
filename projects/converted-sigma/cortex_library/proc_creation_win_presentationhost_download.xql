// Title: Arbitrary File Download Via PresentationHost.EXE
// ID: b124ddf4-778d-418e-907f-6dd3fc0d31cd
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://" or action_process_image_command_line contains "ftp://")) and ((action_process_image_path endswith "\\presentationhost.exe") or (action_process_image_name = "PresentationHost.exe")))
