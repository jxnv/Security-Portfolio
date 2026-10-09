// Title: Potential Goopdate.DLL Sideloading
// ID: b6188d2f-b3c4-4d2c-a17d-9706e0851af0
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "goopdate.dll", a DLL used by googleupdate.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\goopdate.dll") and not (((ImageLoaded startswith "C:\\Program Files (x86)\\" or ImageLoaded startswith "C:\\Program Files\\"))) and not ((((action_process_image_path contains "\\AppData\\Local\\Temp\\GUM" and action_process_image_path contains ".tmp\\Dropbox") and (ImageLoaded contains "\\AppData\\Local\\Temp\\GUM" and ImageLoaded contains ".tmp\\goopdate.dll")) or ((action_process_image_path contains "\\AppData\\Local\\Temp\\GUM" or action_process_image_path contains ":\\Windows\\SystemTemp\\GUM") and action_process_image_path endswith ".tmp\\GoogleUpdate.exe" and (ImageLoaded contains "\\AppData\\Local\\Temp\\GUM" or ImageLoaded contains ":\\Windows\\SystemTemp\\GUM")))))
