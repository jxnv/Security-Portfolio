// Title: Registry Modification Via Regini.EXE
// ID: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
// Status: test
// Level: low
// Author: Eli Salem, Sander Wiebing, oscd.community
// Date: 2020-10-08
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\regini.exe") or (action_process_image_name = "REGINI.EXE")) and not ((action_process_image_command_line ~= ":[^ \\\\]")))
