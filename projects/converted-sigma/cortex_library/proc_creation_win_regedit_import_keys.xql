// Title: Imports Registry Key From a File
// ID: 73bba97f-a82d-42ce-b315-9182e76c57b1
// Status: test
// Level: medium
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-07
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the import of the specified file to the registry with regedit.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " /i " or action_process_image_command_line contains " /s " or action_process_image_command_line contains ".reg")) and ((action_process_image_path endswith "\\regedit.exe") or (action_process_image_name = "REGEDIT.EXE"))) and not ((((action_process_image_command_line contains " -e " or action_process_image_command_line contains " -a " or action_process_image_command_line contains " -c ")) and (action_process_image_command_line ~= ":[^ \\\\]"))))
