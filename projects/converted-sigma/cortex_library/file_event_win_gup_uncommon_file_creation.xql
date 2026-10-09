// Title: Uncommon File Created by Notepad++ Updater Gup.EXE
// ID: 3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-02-03
// Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
// Description: Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations.
// This could indicate potential exploitation of the updater component to deliver unwanted malware or unwarranted files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\gup.exe") and not ((((action_file_path startswith "C:\\Program Files\\Notepad++\\" or action_file_path startswith "C:\\Program Files (x86)\\Notepad++\\")) or (((action_file_path contains "\\plugins\\JsonTools\\testfiles\\" or action_file_path contains "\\Notepad++\\plugins\\ComparePlugin\\")) or ((action_file_path contains "npp." and action_file_path contains ".portable." and action_file_path contains "\\plugins\\"))) or (action_file_path startswith "C:\\$Recycle.Bin\\S-1-5-21") or (action_file_path startswith "C:\\Users\\" and (action_file_path contains "\\AppData\\Local\\Temp\\" and action_file_path contains ".zip")) or (action_file_path startswith "C:\\Users\\" and (action_file_path contains "\\AppData\\Local\\Temp\\" and action_file_path contains "npp." and action_file_path contains ".Installer." and action_file_path contains ".exe")))))
