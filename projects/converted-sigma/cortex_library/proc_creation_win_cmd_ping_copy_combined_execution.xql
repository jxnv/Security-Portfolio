// Title: Potentially Suspicious Ping/Copy Command Combination
// ID: ded2b07a-d12f-4284-9b76-653e37b6c8b0
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-07-18
// Tags: attack.stealth, attack.t1070.004
// Description: Detects uncommon and potentially suspicious one-liner command containing both "ping" and "copy" at the same time, which is usually used by malware.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ping" and action_process_image_command_line contains "copy ")) and (action_process_image_command_line contains " -n ") and (action_process_image_command_line contains " -y ") and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")))
