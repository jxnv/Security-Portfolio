// Title: Load Of RstrtMgr.DLL By An Uncommon Process
// ID: 3669afd2-9891-4534-a626-e5cf03810a61
// Status: test
// Level: low
// Author: Luc Génaux
// Date: 2023-11-28
// Tags: attack.impact, attack.defense-impairment, attack.t1486, attack.t1685
// Description: Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process.
// This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
// It could also be used for anti-analysis purposes by shut downing specific processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded endswith "\\RstrtMgr.dll") or (action_process_image_name = "RstrtMgr.dll")) and not (((action_process_image_path startswith "C:\\Windows\\Temp\\") or ((action_process_image_path startswith "C:\\$WINDOWS.~BT\\" or action_process_image_path startswith "C:\\$WinREAgent\\" or action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\ProgramData\\" or action_process_image_path startswith "C:\\Windows\\explorer.exe" or action_process_image_path startswith "C:\\Windows\\SoftwareDistribution\\" or action_process_image_path startswith "C:\\Windows\\SysNative\\" or action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\" or action_process_image_path startswith "C:\\Windows\\WinSxS\\" or action_process_image_path startswith "C:\\WUDownloadCache\\")) or (action_process_image_path startswith "C:\\Users\\" and (action_process_image_path contains "\\AppData\\Local\\Temp\\is-" and action_process_image_path contains ".tmp\\") and action_process_image_path endswith ".tmp"))) and not (((action_process_image_path startswith "C:\\Users\\" and (action_process_image_path endswith "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" or action_process_image_path endswith "\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")) or (action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Microsoft\\OneDrive\\" and action_process_image_path endswith "\\OneDrive.Sync.Service.exe"))))
