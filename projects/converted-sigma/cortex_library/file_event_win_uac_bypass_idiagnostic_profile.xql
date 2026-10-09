// Title: UAC Bypass Using IDiagnostic Profile - File
// ID: 48ea844d-19b1-4642-944e-fe39c2cc1fec
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-03
// Tags: attack.execution, attack.privilege-escalation, attack.t1548.002
// Description: Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\DllHost.exe" and action_file_path startswith "C:\\Windows\\System32\\" and action_file_path endswith ".dll")
