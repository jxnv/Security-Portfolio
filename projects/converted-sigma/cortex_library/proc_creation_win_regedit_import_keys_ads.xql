// Title: Imports Registry Key From an ADS
// ID: 0b80ade5-6997-4b1d-99a1-71701778ea61
// Status: test
// Level: high
// Author: Oddvar Moe, Sander Wiebing, oscd.community
// Date: 2020-10-12
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the import of a alternate datastream to the registry with regedit.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " /i " or action_process_image_command_line contains ".reg") and action_process_image_command_line ~= ":[^ \\\\]") and ((action_process_image_path endswith "\\regedit.exe") or (action_process_image_name = "REGEDIT.EXE"))) and not (((action_process_image_command_line contains " -e " or action_process_image_command_line contains " -a " or action_process_image_command_line contains " -c "))))
