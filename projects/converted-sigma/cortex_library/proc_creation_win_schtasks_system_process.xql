// Title: Scheduled Task Creation Masquerading as System Processes
// ID: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-02-05
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1053.005, attack.t1036.004, attack.t1036.005
// Description: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " /create " and (action_process_image_command_line contains " audiodg" or action_process_image_command_line contains " conhost" or action_process_image_command_line contains " dwm.exe" or action_process_image_command_line contains " explorer" or action_process_image_command_line contains " lsass" or action_process_image_command_line contains " lsm" or action_process_image_command_line contains " mmc" or action_process_image_command_line contains " msiexec" or action_process_image_command_line contains " regsvr32" or action_process_image_command_line contains " rundll32" or action_process_image_command_line contains " services" or action_process_image_command_line contains " spoolsv" or action_process_image_command_line contains " svchost" or action_process_image_command_line contains " taskeng" or action_process_image_command_line contains " taskhost" or action_process_image_command_line contains " wininit" or action_process_image_command_line contains " winlogon")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
