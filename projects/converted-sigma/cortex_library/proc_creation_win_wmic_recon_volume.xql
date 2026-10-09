// Title: System Disk And Volume Reconnaissance Via Wmic.EXE
// ID: c79da740-5030-45ec-a2e0-479e824a562c
// Status: test
// Level: medium
// Author: Stephen Lincoln '@slincoln-aiq' (AttackIQ)
// Date: 2024-02-02
// Tags: attack.execution, attack.discovery, attack.t1047, attack.t1082
// Description: An adversary might use WMI to discover information about the system, such as the volume name, size,
// free space, and other disk information. This can be done using the 'wmic' command-line utility and has been
// observed being used by threat actors such as Volt Typhoon.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " volumename" or action_process_image_command_line contains " logicaldisk")) or ((action_process_image_command_line contains "path" and action_process_image_command_line contains "win32_logicaldisk")) or ((action_process_image_command_line contains " volume" and action_process_image_command_line contains " list "))) and ((action_process_image_path endswith "\\WMIC.exe") or (action_process_image_name = "wmic.exe")))
