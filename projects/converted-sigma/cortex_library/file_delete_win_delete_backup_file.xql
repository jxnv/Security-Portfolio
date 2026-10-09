// Title: Backup Files Deleted
// ID: 06125661-3814-4e03-bfa2-1e4411c60ac3
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-02
// Tags: attack.impact, attack.t1490
// Description: Detects deletion of files with extensions often used for backup files. Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wt.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\regsvr32.exe") and (action_file_path endswith ".VHD" or action_file_path endswith ".bac" or action_file_path endswith ".bak" or action_file_path endswith ".wbcat" or action_file_path endswith ".bkf" or action_file_path endswith ".set" or action_file_path endswith ".win" or action_file_path endswith ".dsk"))
