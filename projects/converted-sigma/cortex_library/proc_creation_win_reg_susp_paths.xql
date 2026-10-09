// Title: Reg Add Suspicious Paths
// ID: b7e2a8d4-74bb-4b78-adc9-3f92af2d4829
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.persistence, attack.defense-impairment, attack.t1112, attack.t1685
// Description: Detects when an adversary uses the reg.exe utility to add or modify new keys or subkeys
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\AppDataLow\\Software\\Microsoft\\" or action_process_image_command_line contains "\\Policies\\Microsoft\\Windows\\OOBE" or action_process_image_command_line contains "\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" or action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" or action_process_image_command_line contains "\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" or action_process_image_command_line contains "\\Microsoft\\Windows Defender\\")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))
