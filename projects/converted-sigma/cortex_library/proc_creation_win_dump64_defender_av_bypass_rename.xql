// Title: Potential Windows Defender AV Bypass Via Dump64.EXE Rename
// ID: 129966c9-de17-4334-a123-8b58172e664d
// Status: test
// Level: high
// Author: Austin Songer @austinsonger, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-11-26
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects when a user is potentially trying to bypass the Windows Defender AV by renaming a tool to dump64.exe and placing it in the Visual Studio folder.
// Currently the rule is covering only usage of procdump but other utilities can be added in order to increase coverage.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path startswith ":\\Program Files" and action_process_image_path contains "\\Microsoft Visual Studio\\" and action_process_image_path endswith "\\dump64.exe") and ((action_process_image_name = "procdump") or ((action_process_image_command_line contains " -ma " or action_process_image_command_line contains " -mp "))))
