// Title: Clfs.SYS Loaded By Process Located In a Potential Suspicious Location
// ID: fb4e2211-6d08-426b-8e6f-0d4a161e3b1d
// Status: experimental
// Level: medium
// Author: X__Junior
// Date: 2025-01-20
// Tags: attack.execution, attack.t1059
// Description: Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\clfs.sys") and (((action_process_image_path contains ":\\Perflogs\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains "\\Temporary Internet" or action_process_image_path contains "\\Windows\\Temp\\")) or (((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Favorites\\")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Favourites\\")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Contacts\\")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Pictures\\")))))
