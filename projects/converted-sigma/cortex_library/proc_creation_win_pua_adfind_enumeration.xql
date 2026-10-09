// Title: PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE
// ID: 455b9d50-15a1-4b99-853f-8d37655a4c1b
// Status: test
// Level: high
// Author: frack113
// Date: 2021-12-13
// Tags: attack.discovery, attack.t1087.002
// Description: Detects active directory enumeration activity using known AdFind CLI flags
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "-sc admincountdmp") or (action_process_image_command_line contains "-sc exchaddresses") or ((action_process_image_command_line contains "lockoutduration" or action_process_image_command_line contains "lockoutthreshold" or action_process_image_command_line contains "lockoutobservationwindow" or action_process_image_command_line contains "maxpwdage" or action_process_image_command_line contains "minpwdage" or action_process_image_command_line contains "minpwdlength" or action_process_image_command_line contains "pwdhistorylength" or action_process_image_command_line contains "pwdproperties")))
