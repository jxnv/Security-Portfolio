// Title: HackTool - SharpDPAPI Execution
// ID: c7d33b50-f690-4b51-8cfb-0fb912a31e57
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-06-26
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.003
// Description: Detects the execution of the SharpDPAPI tool based on CommandLine flags and PE metadata.
// SharpDPAPI is a C# port of some DPAPI functionality from the Mimikatz project.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\SharpDPAPI.exe") or (action_process_image_name = "SharpDPAPI.exe")) or (((action_process_image_command_line contains " backupkey " or action_process_image_command_line contains " blob " or action_process_image_command_line contains " certificates " or action_process_image_command_line contains " credentials " or action_process_image_command_line contains " keepass " or action_process_image_command_line contains " masterkeys " or action_process_image_command_line contains " rdg " or action_process_image_command_line contains " vaults ")) and (((action_process_image_command_line contains " /file:" or action_process_image_command_line contains " /machine" or action_process_image_command_line contains " /mkfile:" or action_process_image_command_line contains " /password:" or action_process_image_command_line contains " /pvk:" or action_process_image_command_line contains " /server:" or action_process_image_command_line contains " /target:" or action_process_image_command_line contains " /unprotect")) or ((action_process_image_command_line contains " {" and action_process_image_command_line contains "}:")))))
