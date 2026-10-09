// Title: Regsvr32 DLL Execution With Uncommon Extension
// ID: 50919691-7302-437f-8e10-1fe088afa145
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-07-17
// Tags: attack.privilege-escalation, attack.persistence, attack.stealth, attack.t1574, attack.execution
// Description: Detects a "regsvr32" execution where the DLL doesn't contain a common file extension.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\regsvr32.exe") or (action_process_image_name = "REGSVR32.EXE")) and not (((action_process_image_command_line = "") or ((action_process_image_command_line contains ".ax" or action_process_image_command_line contains ".cpl" or action_process_image_command_line contains ".dll" or action_process_image_command_line contains ".ocx")) or (action_process_image_command_line = null))) and not (((action_process_image_command_line contains ".bav") or (action_process_image_command_line contains ".ppl"))))
