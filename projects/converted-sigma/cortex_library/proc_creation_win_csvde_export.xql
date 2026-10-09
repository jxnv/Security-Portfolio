// Title: Active Directory Structure Export Via Csvde.EXE
// ID: e5d36acd-acb4-4c6f-a13f-9eb203d50099
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-14
// Tags: attack.exfiltration, attack.discovery, attack.t1087.002
// Description: Detects the execution of "csvde.exe" in order to export organizational Active Directory structure.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\csvde.exe") or (action_process_image_name = "csvde.exe")) and (action_process_image_command_line contains " -f")) and not ((action_process_image_command_line contains " -i")))
