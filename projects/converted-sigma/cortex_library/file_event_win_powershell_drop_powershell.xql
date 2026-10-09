// Title: PowerShell Script Dropped Via PowerShell.EXE
// ID: 576426ad-0131-4001-ae01-be175da0c108
// Status: test
// Level: low
// Author: frack113
// Date: 2023-05-09
// Tags: attack.persistence
// Description: Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and action_file_path endswith ".ps1") and not (((action_file_path startswith "C:\\Users\\" and action_file_path contains "\\AppData\\Local\\Temp\\") or (action_file_path contains "__PSScriptPolicyTest_") or (action_file_path startswith "C:\\Windows\\Temp\\"))))
