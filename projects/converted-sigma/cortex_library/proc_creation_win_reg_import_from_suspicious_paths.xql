// Title: Potential Suspicious Registry File Imported Via Reg.EXE
// ID: 62e0298b-e994-4189-bc87-bc699aa62d97
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-08-01
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " import ") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")) and ((action_process_image_command_line contains "C:\\Users\\" or action_process_image_command_line contains "%temp%" or action_process_image_command_line contains "%tmp%" or action_process_image_command_line contains "%appdata%" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "C:\\Windows\\Temp\\" or action_process_image_command_line contains "C:\\ProgramData\\")))
