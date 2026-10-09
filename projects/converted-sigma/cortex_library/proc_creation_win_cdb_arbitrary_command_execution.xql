// Title: Potential Binary Proxy Execution Via Cdb.EXE
// ID: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
// Status: test
// Level: medium
// Author: Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-10-26
// Tags: attack.execution, attack.stealth, attack.t1106, attack.t1218, attack.t1127
// Description: Detects usage of "cdb.exe" to launch arbitrary processes or commands from a debugger script file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -c " or action_process_image_command_line contains " -cf ")) and ((action_process_image_path endswith "\\cdb.exe") or (action_process_image_name = "CDB.Exe")))
