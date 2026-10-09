// Title: Self Extraction Directive File Created In Potentially Suspicious Location
// ID: 760e75d8-c3b5-409b-a9bf-6130b4c4603f
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2024-02-05
// Tags: attack.stealth, attack.t1218
// Description: Detects the creation of Self Extraction Directive files (.sed) in a potentially suspicious location.
// These files are used by the "iexpress.exe" utility in order to create self extracting packages.
// Attackers were seen abusing this utility and creating PE files with embedded ".sed" entries.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains ":\\ProgramData\\" or action_file_path contains ":\\Temp\\" or action_file_path contains ":\\Windows\\System32\\Tasks\\" or action_file_path contains ":\\Windows\\Tasks\\" or action_file_path contains ":\\Windows\\Temp\\" or action_file_path contains "\\AppData\\Local\\Temp\\") and action_file_path endswith ".sed")
