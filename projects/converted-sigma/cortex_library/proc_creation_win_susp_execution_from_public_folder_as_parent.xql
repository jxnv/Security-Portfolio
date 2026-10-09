// Title: Potentially Suspicious Execution From Parent Process In Public Folder
// ID: 69bd9b97-2be2-41b6-9816-fb08757a4d1a
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-02-25
// Tags: attack.execution, attack.stealth, attack.t1564, attack.t1059
// Description: Detects a potentially suspicious execution of a parent process located in the "\Users\Public" folder executing a child process containing references to shell or scripting binaries and commandlines.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_command_line contains "bitsadmin" or action_process_image_command_line contains "certutil" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "wscript"))) and (actor_process_image_path contains ":\\Users\\Public\\"))
