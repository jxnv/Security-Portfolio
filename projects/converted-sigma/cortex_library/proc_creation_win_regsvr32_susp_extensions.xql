// Title: Regsvr32 DLL Execution With Suspicious File Extension
// ID: 089fc3d2-71e8-4763-a8a5-c97fbb0a403e
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), frack113
// Date: 2021-11-29
// Tags: attack.stealth, attack.t1218.010
// Description: Detects the execution of REGSVR32.exe with DLL files masquerading as other files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith ".bin" or action_process_image_command_line endswith ".bmp" or action_process_image_command_line endswith ".cr2" or action_process_image_command_line endswith ".dat" or action_process_image_command_line endswith ".eps" or action_process_image_command_line endswith ".gif" or action_process_image_command_line endswith ".ico" or action_process_image_command_line endswith ".jpeg" or action_process_image_command_line endswith ".jpg" or action_process_image_command_line endswith ".log" or action_process_image_command_line endswith ".nef" or action_process_image_command_line endswith ".orf" or action_process_image_command_line endswith ".png" or action_process_image_command_line endswith ".raw" or action_process_image_command_line endswith ".rtf" or action_process_image_command_line endswith ".sr2" or action_process_image_command_line endswith ".temp" or action_process_image_command_line endswith ".tif" or action_process_image_command_line endswith ".tiff" or action_process_image_command_line endswith ".tmp" or action_process_image_command_line endswith ".txt")) and ((action_process_image_path endswith "\\regsvr32.exe") or (action_process_image_name = "REGSVR32.EXE")))
