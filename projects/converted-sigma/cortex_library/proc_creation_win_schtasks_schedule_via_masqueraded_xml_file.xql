// Title: Suspicious Scheduled Task Creation via Masqueraded XML File
// ID: dd2a821e-3b07-4d3b-a9ac-929fe4c6ca0c
// Status: test
// Level: medium
// Author: Swachchhanda Shrawan Poudel, Elastic (idea)
// Date: 2023-04-20
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1036.005, attack.t1053.005
// Description: Detects the creation of a scheduled task using the "-XML" flag with a file without the '.xml' extension. This behavior could be indicative of potential defense evasion attempt during persistence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "/create" or action_process_image_command_line contains "-create")) and ((action_process_image_command_line contains "/xml" or action_process_image_command_line contains "-xml")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe"))) and not (((action_process_image_command_line contains ".xml") or (actor_process_image_path endswith "\\rundll32.exe" and (actor_process_command_line contains ":\\WINDOWS\\Installer\\MSI" and actor_process_command_line contains ".tmp,zzzzInvokeManagedCustomActionOutOfProc")) or ((IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384")))) and not (((actor_process_image_path endswith ":\\ProgramData\\OEM\\UpgradeTool\\CareCenter_*\\BUnzip\\Setup_msi.exe" or actor_process_image_path endswith ":\\Program Files\\Axis Communications\\AXIS Camera Station\\SetupActions.exe" or actor_process_image_path endswith ":\\Program Files\\Axis Communications\\AXIS Device Manager\\AdmSetupActions.exe" or actor_process_image_path endswith ":\\Program Files (x86)\\Zemana\\AntiMalware\\AntiMalware.exe" or actor_process_image_path endswith ":\\Program Files\\Dell\\SupportAssist\\pcdrcui.exe"))))
