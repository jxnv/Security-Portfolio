// Title: Desktop.INI Created by Uncommon Process
// ID: 81315b50-6b60-4d8f-9928-3466e1022515
// Status: test
// Level: medium
// Author: Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)
// Date: 2020-03-19
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.009
// Description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\desktop.ini") and not ((((action_process_image_path startswith "C:\\Windows\\" or action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\")) or (action_file_path startswith "C:\\$WINDOWS.~BT\\NewOS\\"))) and not (((action_process_image_path startswith "C:\\Users\\" and action_process_image_path endswith "\\AppData\\Local\\JetBrains\\Toolbox\\bin\\7z.exe" and action_file_path contains "\\JetBrains\\apps\\") or (action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Microsoft\\OneDrive\\"))))
