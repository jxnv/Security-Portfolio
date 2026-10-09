// Title: File With Uncommon Extension Created By An Office Application
// ID: c7a74c80-ba5a-486e-9974-ab9e682bc5e4
// Status: test
// Level: high
// Author: Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.t1204.002, attack.execution
// Description: Detects the creation of files with an executable or script extension by an Office application.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\msaccess.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\visio.exe" or action_process_image_path endswith "\\winword.exe")) and ((action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".com" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".ocx" or action_file_path endswith ".proj" or action_file_path endswith ".ps1" or action_file_path endswith ".scf" or action_file_path endswith ".scr" or action_file_path endswith ".sys" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf" or action_file_path endswith ".wsh"))) and not ((action_file_path contains "\\AppData\\Local\\assembly\\tmp\\" and action_file_path endswith ".dll")) and not ((((action_file_path contains "C:\\Users\\" and action_file_path contains "\\AppData\\Local\\Microsoft\\Office\\" and action_file_path contains "\\BackstageInAppNavCache\\") and action_file_path endswith ".com") or (action_process_image_path endswith "\\winword.exe" and action_file_path contains "\\AppData\\Local\\Temp\\webexdelta\\" and (action_file_path endswith ".dll" or action_file_path endswith ".exe")) or ((action_file_path contains "C:\\Users\\" and action_file_path contains "\\AppData\\Local\\Microsoft\\Office\\" and action_file_path contains "\\WebServiceCache\\AllUsers") and action_file_path endswith ".com"))))
