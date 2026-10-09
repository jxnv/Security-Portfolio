// Title: Potential CCleanerReactivator.DLL Sideloading
// ID: 3735d5ac-d770-4da0-99ff-156b180bc600
// Status: test
// Level: medium
// Author: X__Junior
// Date: 2023-07-13
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "CCleanerReactivator.dll"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\CCleanerReactivator.dll") and not (((action_process_image_path startswith "C:\\Program Files\\CCleaner\\" or action_process_image_path startswith "C:\\Program Files (x86)\\CCleaner\\") and action_process_image_path endswith "\\CCleanerReactivator.exe")))
