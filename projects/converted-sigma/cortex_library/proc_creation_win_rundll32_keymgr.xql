// Title: Suspicious Key Manager Access
// ID: a4694263-59a8-4608-a3a0-6f8d3a51664c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-21
// Tags: attack.credential-access, attack.t1555.004
// Description: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "keymgr" and action_process_image_command_line contains "KRShowKeyMgr")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
