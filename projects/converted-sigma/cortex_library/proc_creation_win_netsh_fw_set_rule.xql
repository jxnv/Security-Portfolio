// Title: Firewall Rule Update Via Netsh.EXE
// ID: a70dcb37-3bee-453a-99df-d0c683151be6
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-07-18
// Tags: attack.defense-impairment
// Description: Detects execution of netsh with the "advfirewall" and the "set" option in order to set new values for properties of a existing rule
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " firewall " and action_process_image_command_line contains " set ")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
