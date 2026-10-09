// Title: Suspicious WMIC Execution Via Office Process
// ID: e1693bc8-7168-4eab-8718-cdcaa68a1738
// Status: test
// Level: high
// Author: Vadim Khrykov, Cyb3rEng
// Date: 2021-08-23
// Tags: attack.stealth, attack.t1204.002, attack.t1047, attack.t1218.010, attack.execution
// Description: Office application called wmic to proxye execution through a LOLBIN process. This is often used to break suspicious parent-child chain (Office app spawns LOLBin).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\WINWORD.EXE" or actor_process_image_path endswith "\\EXCEL.EXE" or actor_process_image_path endswith "\\POWERPNT.exe" or actor_process_image_path endswith "\\MSPUB.exe" or actor_process_image_path endswith "\\VISIO.exe" or actor_process_image_path endswith "\\MSACCESS.EXE" or actor_process_image_path endswith "\\EQNEDT32.EXE" or actor_process_image_path endswith "\\ONENOTE.EXE" or actor_process_image_path endswith "\\wordpad.exe" or actor_process_image_path endswith "\\wordview.exe")) and ((action_process_image_command_line contains "process" and action_process_image_command_line contains "create" and action_process_image_command_line contains "call") and (action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "msiexec" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "verclsid" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "cscript")) and ((action_process_image_path endswith "\\wbem\\WMIC.exe") or (action_process_image_name = "wmic.exe")))
