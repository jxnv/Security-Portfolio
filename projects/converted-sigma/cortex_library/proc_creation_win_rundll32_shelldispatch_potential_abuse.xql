// Title: Potential ShellDispatch.DLL Functionality Abuse
// ID: 82343930-652f-43f5-ab70-2ee9fdd6d5e9
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-20
// Tags: attack.execution, attack.stealth
// Description: Detects potential "ShellDispatch.dll" functionality abuse to execute arbitrary binaries via "ShellExecute"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "RunDll_ShellExecuteW") and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
