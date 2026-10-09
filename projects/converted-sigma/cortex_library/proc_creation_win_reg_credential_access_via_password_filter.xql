// Title: Dropping Of Password Filter DLL
// ID: b7966f4a-b333-455b-8370-8ca53c229762
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-10-29
// Tags: attack.persistence, attack.credential-access, attack.defense-impairment, attack.t1556.002
// Description: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" and action_process_image_command_line contains "scecli\\0*" and action_process_image_command_line contains "reg add"))
