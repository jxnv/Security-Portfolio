// Title: Process Memory Dump via RdrLeakDiag.EXE
// ID: edadb1e5-5919-4e4c-8462-a9e643b02c4b
// Status: test
// Level: high
// Author: Cedric MAURUGEON, Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-09-24
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the use of the Microsoft Windows Resource Leak Diagnostic tool "rdrleakdiag.exe" to dump process memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/memdmp" or action_process_image_command_line contains "-memdmp" or action_process_image_command_line contains "fullmemdmp")) and ((action_process_image_command_line contains " /o " or action_process_image_command_line contains " /p ")) and ((action_process_image_path endswith "\\rdrleakdiag.exe") or (action_process_image_name = "RdrLeakDiag.exe")))
