// Title: Gpscript Execution
// ID: 1e59c230-6670-45bf-83b0-98903780607e
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-05-16
// Tags: attack.stealth, attack.t1218
// Description: Detects the execution of the LOLBIN gpscript, which executes logon or startup scripts configured in Group Policy
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " /logon" or action_process_image_command_line contains " /startup")) and ((action_process_image_path endswith "\\gpscript.exe") or (action_process_image_name = "GPSCRIPT.EXE"))) and not ((actor_process_command_line = "C:\\windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc")))
