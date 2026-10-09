// Title: Suspicious Rundll32 Execution With Image Extension
// ID: 4aa6040b-3f28-44e3-a769-9208e5feb5ec
// Status: test
// Level: high
// Author: Hieu Tran
// Date: 2023-03-13
// Tags: attack.stealth, attack.t1218.011
// Description: Detects the execution of Rundll32.exe with DLL files masquerading as image files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".bmp" or action_process_image_command_line contains ".cr2" or action_process_image_command_line contains ".eps" or action_process_image_command_line contains ".gif" or action_process_image_command_line contains ".ico" or action_process_image_command_line contains ".jpeg" or action_process_image_command_line contains ".jpg" or action_process_image_command_line contains ".nef" or action_process_image_command_line contains ".orf" or action_process_image_command_line contains ".png" or action_process_image_command_line contains ".raw" or action_process_image_command_line contains ".sr2" or action_process_image_command_line contains ".tif" or action_process_image_command_line contains ".tiff")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.exe")))
