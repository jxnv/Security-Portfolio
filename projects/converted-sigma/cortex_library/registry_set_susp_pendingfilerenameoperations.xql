// Title: Potential PendingFileRenameOperations Tampering
// ID: 4eec988f-7bf0-49f1-8675-1e6a510b3a2a
// Status: test
// Level: medium
// Author: frack113
// Date: 2023-01-27
// Tags: attack.stealth, attack.t1036.003
// Description: Detect changes to the "PendingFileRenameOperations" registry key from uncommon or suspicious images locations to stage currently used files for rename or deletion after reboot.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations") and (((action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\regedit.exe")) or (action_process_image_path contains "\\Users\\Public\\")))
