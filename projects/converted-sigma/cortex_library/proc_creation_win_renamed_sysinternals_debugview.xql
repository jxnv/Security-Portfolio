// Title: Renamed SysInternals DebugView Execution
// ID: cd764533-2e07-40d6-a718-cfeec7f2da7f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-05-28
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects suspicious renamed SysInternals DebugView execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Product = "Sysinternals DebugView") and not ((action_process_image_name = "Dbgview.exe" and action_process_image_path endswith "\\Dbgview.exe")))
