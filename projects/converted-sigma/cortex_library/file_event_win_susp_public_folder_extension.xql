// Title: Suspicious Binaries and Scripts in Public Folder
// ID: b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e
// Status: experimental
// Level: high
// Author: The DFIR Report
// Date: 2025-01-23
// Tags: attack.execution, attack.t1204
// Description: Detects the creation of a file with a suspicious extension in the public folder, which could indicate potential malicious activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path contains ":\\Users\\Public\\" and (action_file_path endswith ".bat" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".js" or action_file_path endswith ".ps1" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs"))
