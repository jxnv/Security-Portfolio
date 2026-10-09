// Title: Potential NTLM Coercion Via Certutil.EXE
// ID: 6c6d9280-e6d0-4b9d-80ac-254701b64916
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-01
// Tags: attack.stealth, attack.t1218
// Description: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -syncwithWU " and action_process_image_command_line contains " \\\\\\\\")) and ((action_process_image_path endswith "\\certutil.exe") or (action_process_image_name = "CertUtil.exe")))
