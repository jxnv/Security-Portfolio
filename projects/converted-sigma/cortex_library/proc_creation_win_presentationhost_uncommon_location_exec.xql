// Title: XBAP Execution From Uncommon Locations Via PresentationHost.EXE
// ID: d22e2925-cfd8-463f-96f6-89cec9d9bc5f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-01
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects the execution of ".xbap" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious ".xbap" files any bypass AWL
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".xbap") and ((action_process_image_path endswith "\\presentationhost.exe") or (action_process_image_name = "PresentationHost.exe"))) and not (((action_process_image_command_line contains " C:\\Windows\\" or action_process_image_command_line contains " C:\\Program Files"))))
