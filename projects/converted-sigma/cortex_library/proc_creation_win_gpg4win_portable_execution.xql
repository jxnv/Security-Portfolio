// Title: Portable Gpg.EXE Execution
// ID: 77df53a5-1d78-4f32-bc5a-0e7465bd8f41
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-06
// Tags: attack.impact, attack.t1486
// Description: Detects the execution of "gpg.exe" from uncommon location. Often used by ransomware and loaders to decrypt/encrypt data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\gpg.exe" or action_process_image_path endswith "\\gpg2.exe")) or (action_process_image_name = "gpg.exe") or (Description = "GnuPG’s OpenPGP tool")) and not (((action_process_image_path contains ":\\Program Files (x86)\\GNU\\GnuPG\\bin\\" or action_process_image_path contains ":\\Program Files (x86)\\GnuPG VS-Desktop\\" or action_process_image_path contains ":\\Program Files (x86)\\GnuPG\\bin\\" or action_process_image_path contains ":\\Program Files (x86)\\Gpg4win\\bin\\"))))
