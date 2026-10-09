// Title: Active Directory Structure Export Via Ldifde.EXE
// ID: 4f7a6757-ff79-46db-9687-66501a02d9ec
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-14
// Tags: attack.exfiltration
// Description: Detects the execution of "ldifde.exe" in order to export organizational Active Directory structure.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-f") and ((action_process_image_path endswith "\\ldifde.exe") or (action_process_image_name = "ldifde.exe"))) and not ((action_process_image_command_line contains " -i")))
