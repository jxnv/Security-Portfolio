// Title: Potential WWlib.DLL Sideloading
// ID: e2e01011-5910-4267-9c3b-4149ed5479cf
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-05-18
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "wwlib.dll"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\wwlib.dll") and not (((action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft Office\\" or action_process_image_path startswith "C:\\Program Files\\Microsoft Office\\") and action_process_image_path endswith "\\winword.exe" and (ImageLoaded startswith "C:\\Program Files (x86)\\Microsoft Office\\" or ImageLoaded startswith "C:\\Program Files\\Microsoft Office\\"))))
