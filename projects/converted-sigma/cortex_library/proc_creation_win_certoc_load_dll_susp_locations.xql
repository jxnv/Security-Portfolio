// Title: Suspicious DLL Loaded via CertOC.EXE
// ID: 84232095-ecca-4015-b0d7-7726507ee793
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-15
// Tags: attack.stealth, attack.t1218
// Description: Detects when a user installs certificates by using CertOC.exe to load the target DLL file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -LoadDLL ") and ((action_process_image_path endswith "\\certoc.exe") or (action_process_image_name = "CertOC.exe")) and ((action_process_image_command_line contains "\\Appdata\\Local\\Temp\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "C:\\Windows\\Tasks\\" or action_process_image_command_line contains "C:\\Windows\\Temp\\")))
