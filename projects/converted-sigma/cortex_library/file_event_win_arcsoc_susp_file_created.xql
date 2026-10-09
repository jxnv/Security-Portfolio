// Title: Suspicious File Created by ArcSOC.exe
// ID: e890acee-d488-420e-8f20-d9b19b3c3d43
// Status: experimental
// Level: high
// Author: Micah Babinski
// Date: 2025-11-25
// Tags: attack.command-and-control, attack.persistence, attack.initial-access, attack.execution, attack.stealth, attack.t1127, attack.t1105, attack.t1133
// Description: Detects instances where the ArcGIS Server process ArcSOC.exe, which hosts REST services running on an ArcGIS
// server, creates a file with suspicious file type, indicating that it may be an executable, script file,
// or otherwise unusual.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\ArcSOC.exe" and (action_file_path endswith ".ahk" or action_file_path endswith ".aspx" or action_file_path endswith ".au3" or action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".js" or action_file_path endswith ".ps1" or action_file_path endswith ".py" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf"))
