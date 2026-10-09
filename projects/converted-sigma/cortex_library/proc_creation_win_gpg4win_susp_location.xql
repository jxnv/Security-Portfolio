// Title: File Encryption/Decryption Via Gpg4win From Suspicious Locations
// ID: e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
// Date: 2022-11-30
// Tags: attack.execution
// Description: Detects usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "-passphrase") and (((action_process_image_path endswith "\\gpg.exe" or action_process_image_path endswith "\\gpg2.exe")) or (Product = "GNU Privacy Guard (GnuPG)") or (Description = "GnuPG’s OpenPGP tool")) and ((action_process_image_command_line contains ":\\PerfLogs\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\AppData\\Roaming\\")))
