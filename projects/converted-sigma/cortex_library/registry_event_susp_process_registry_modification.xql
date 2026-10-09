// Title: Registry Tampering by Potentially Suspicious Processes
// ID: 7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-08-13
// Tags: attack.persistence, attack.execution, attack.defense-impairment, attack.t1112, attack.t1059.005
// Description: Detects suspicious registry modifications made by suspicious processes such as script engine processes such as WScript, or CScript etc.
// These processes are rarely used for legitimate registry modifications, and their activity may indicate an attempt to modify the registry
// without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe")) and not (((Details = "Binary Data") or (Details = null) or (action_process_image_path endswith "\\wscript.exe" and (TargetObject contains "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data\\" or TargetObject contains "\\Services\\bam\\State\\UserSettings\\S-1-" or TargetObject contains "Software\\Microsoft\\Windows Script\\Settings\\Telemetry\\wscript.exe\\" or TargetObject contains "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\")) or (action_process_image_path endswith "\\wscript.exe" and TargetObject contains "\\wscript.exe"))))
