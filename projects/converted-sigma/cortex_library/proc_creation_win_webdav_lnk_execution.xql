// Title: Potentially Suspicious WebDAV LNK Execution
// ID: 1412aa78-a24c-4abd-83df-767dfb2c5bbe
// Status: test
// Level: medium
// Author: Micah Babinski
// Date: 2023-08-21
// Tags: attack.execution, attack.t1059.001, attack.t1204
// Description: Detects possible execution via LNK file accessed on a WebDAV server.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\explorer.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe") and action_process_image_command_line contains "\\DavWWWRoot\\")
