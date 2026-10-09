// Title: File Encryption Using Gpg4win
// ID: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-09
// Tags: attack.execution
// Description: Detects usage of Gpg4win to encrypt files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -c " and action_process_image_command_line contains "passphrase")) and (((action_process_image_path endswith "\\gpg.exe" or action_process_image_path endswith "\\gpg2.exe")) or (Description = "GnuPG’s OpenPGP tool")))
