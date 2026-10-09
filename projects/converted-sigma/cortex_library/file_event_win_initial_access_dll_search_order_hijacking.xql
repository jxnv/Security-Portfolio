// Title: Potential Initial Access via DLL Search Order Hijacking
// ID: dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c
// Status: test
// Level: medium
// Author: Tim Rauch (rule), Elastic (idea)
// Date: 2022-10-21
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1566, attack.t1566.001, attack.initial-access, attack.t1574, attack.t1574.001
// Description: Detects attempts to create a DLL file to a known desktop application dependencies folder such as Slack, Teams or OneDrive and by an unusual process. This may indicate an attempt to load a malicious module via DLL search order hijacking.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\winword.exe" or action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\MSACCESS.EXE" or action_process_image_path endswith "\\MSPUB.EXE" or action_process_image_path endswith "\\fltldr.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and action_file_path endswith ".dll" and (action_file_path contains "\\Users\\" and action_file_path contains "\\AppData\\") and (action_file_path contains "\\Microsoft\\OneDrive\\" or action_file_path contains "\\Microsoft OneDrive\\" or action_file_path contains "\\Microsoft\\Teams\\" or action_file_path contains "\\Local\\slack\\app-" or action_file_path contains "\\Local\\Programs\\Microsoft VS Code\\")) and not ((action_process_image_path endswith "\\cmd.exe" and (action_file_path contains "\\Users\\" and action_file_path contains "\\AppData\\" and action_file_path contains "\\Microsoft\\OneDrive\\" and action_file_path contains "\\api-ms-win-core-"))))
