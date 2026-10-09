// Title: Suspicious VBoxDrvInst.exe Parameters
// ID: b7b19cb6-9b32-4fc4-a108-73f19acfe262
// Status: test
// Level: medium
// Author: Konstantin Grishchenko, oscd.community
// Date: 2020-10-06
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detect VBoxDrvInst.exe run with parameters allowing processing INF file.
// This allows to create values in the registry and install drivers.
// For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\VBoxDrvInst.exe" and (action_process_image_command_line contains "driver" and action_process_image_command_line contains "executeinf"))
