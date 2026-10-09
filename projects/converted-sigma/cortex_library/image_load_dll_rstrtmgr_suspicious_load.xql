// Title: Load Of RstrtMgr.DLL By A Suspicious Process
// ID: b48492dc-c5ef-4572-8dff-32bc241c15c8
// Status: test
// Level: high
// Author: Luc Génaux
// Date: 2023-11-28
// Tags: attack.impact, attack.defense-impairment, attack.t1486, attack.t1685
// Description: Detects the load of RstrtMgr DLL (Restart Manager) by a suspicious process.
// This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
// It could also be used for anti-analysis purposes by shut downing specific processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded endswith "\\RstrtMgr.dll") or (action_process_image_name = "RstrtMgr.dll")) and (((action_process_image_path contains ":\\Perflogs\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains "\\Temporary Internet")) or (((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Favorites\\")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Favourites\\")) or ((action_process_image_path contains ":\\Users\\" and action_process_image_path contains "\\Contacts\\")))))
