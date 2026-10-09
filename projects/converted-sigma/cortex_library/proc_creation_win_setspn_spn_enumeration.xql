// Title: Potential SPN Enumeration Via Setspn.EXE
// ID: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
// Status: test
// Level: medium
// Author: Markus Neis, keepwatch
// Date: 2018-11-14
// Tags: attack.credential-access, attack.t1558.003
// Description: Detects service principal name (SPN) enumeration used for Kerberoasting
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -q " or action_process_image_command_line contains " /q ")) and ((action_process_image_path endswith "\\setspn.exe") or (action_process_image_name = "setspn.exe") or ((Description contains "Query or reset the computer" and Description contains "SPN attribute"))))
