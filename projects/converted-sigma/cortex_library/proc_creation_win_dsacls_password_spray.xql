// Title: Potential Password Spraying Attempt Using Dsacls.EXE
// ID: bac9fb54-2da7-44e9-988f-11e9a5edbc0c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.stealth, attack.t1218
// Description: Detects possible password spraying attempts using Dsacls
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/user:" and action_process_image_command_line contains "/passwd:")) and ((action_process_image_path endswith "\\dsacls.exe") or (action_process_image_name = "DSACLS.EXE")))
