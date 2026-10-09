// Title: Execution via stordiag.exe
// ID: 961e0abb-1b1e-4c84-a453-aafe56ad0d34
// Status: test
// Level: high
// Author: Austin Songer (@austinsonger)
// Date: 2021-10-21
// Tags: attack.stealth, attack.t1218
// Description: Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\stordiag.exe" and (action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\fltmc.exe")) and not (((actor_process_image_path startswith "c:\\windows\\system32\\" or actor_process_image_path startswith "c:\\windows\\syswow64\\"))))
