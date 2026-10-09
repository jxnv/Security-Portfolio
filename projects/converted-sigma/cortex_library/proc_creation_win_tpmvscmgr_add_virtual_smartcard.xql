// Title: New Virtual Smart Card Created Via TpmVscMgr.EXE
// ID: c633622e-cab9-4eaa-bb13-66a1d68b3e47
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-15
// Tags: attack.execution
// Description: Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "create") and (action_process_image_path endswith "\\tpmvscmgr.exe" and action_process_image_name = "TpmVscMgr.exe"))
