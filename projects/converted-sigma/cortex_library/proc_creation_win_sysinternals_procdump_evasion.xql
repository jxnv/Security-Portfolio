// Title: Potential SysInternals ProcDump Evasion
// ID: 79b06761-465f-4f88-9ef2-150e24d3d737
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-11
// Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
// Description: Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "copy procdump" or action_process_image_command_line contains "move procdump")) or ((action_process_image_command_line contains "copy " and action_process_image_command_line contains ".dmp ") and (action_process_image_command_line contains "2.dmp" or action_process_image_command_line contains "lsass" or action_process_image_command_line contains "out.dmp")) or ((action_process_image_command_line contains "copy lsass.exe_" or action_process_image_command_line contains "move lsass.exe_")))
