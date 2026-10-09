// Title: Potential Persistence Via Netsh Helper DLL
// ID: 56321594-9087-49d9-bf10-524fe8479452
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.007, attack.s0108
// Description: Detects the execution of netsh with "add helper" flag in order to add a custom helper DLL. This technique can be abused to add a malicious helper DLL that can be used as a persistence proxy that gets called when netsh.exe is executed.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "add" and action_process_image_command_line contains "helper")) and ((action_process_image_name = "netsh.exe") or (action_process_image_path endswith "\\netsh.exe")))
