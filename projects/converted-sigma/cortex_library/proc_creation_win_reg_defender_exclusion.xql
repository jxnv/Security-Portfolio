// Title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
// ID: 48917adc-a28e-4f5d-b729-11e75da8941f
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-13
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\reg.exe" and (action_process_image_command_line contains "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" or action_process_image_command_line contains "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths") and (action_process_image_command_line contains "ADD " and action_process_image_command_line contains "/t " and action_process_image_command_line contains "REG_DWORD " and action_process_image_command_line contains "/v " and action_process_image_command_line contains "/d " and action_process_image_command_line contains "0"))
