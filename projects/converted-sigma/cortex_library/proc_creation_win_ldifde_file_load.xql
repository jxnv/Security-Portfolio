// Title: Import LDAP Data Interchange Format File Via Ldifde.EXE
// ID: 6f535e01-ca1f-40be-ab8d-45b19c0c8b7f
// Status: test
// Level: medium
// Author: @gott_cyber
// Date: 2022-09-02
// Tags: attack.command-and-control, attack.stealth, attack.t1218, attack.t1105
// Description: Detects the execution of "Ldifde.exe" with the import flag "-i". The can be abused to include HTTP-based arguments which will allow the arbitrary download of files from a remote server.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-i" and action_process_image_command_line contains "-f")) and ((action_process_image_path endswith "\\ldifde.exe") or (action_process_image_name = "ldifde.exe")))
