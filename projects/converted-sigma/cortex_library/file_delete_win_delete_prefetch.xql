// Title: Prefetch File Deleted
// ID: 0a1f9d29-6465-4776-b091-7f43b26e4c89
// Status: test
// Level: high
// Author: Cedric MAURUGEON
// Date: 2021-09-29
// Tags: attack.stealth, attack.t1070.004
// Description: Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains ":\\Windows\\Prefetch\\" and action_file_path endswith ".pf") and not ((action_process_image_path endswith ":\\windows\\system32\\svchost.exe" and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI"))))
