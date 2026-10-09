// Title: File Decryption Using Gpg4win
// ID: 037dcd71-33a8-4392-bb01-293c94663e5a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-09
// Tags: attack.execution
// Description: Detects usage of Gpg4win to decrypt files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -d " and action_process_image_command_line contains "passphrase")) and (((action_process_image_path endswith "\\gpg.exe" or action_process_image_path endswith "\\gpg2.exe")) or (Description = "GnuPG’s OpenPGP tool")))
