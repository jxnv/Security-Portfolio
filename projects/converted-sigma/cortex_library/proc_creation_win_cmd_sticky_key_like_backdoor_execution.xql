// Title: Sticky Key Like Backdoor Execution
// ID: 2fdefcb3-dbda-401e-ae23-f0db027628bc
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community
// Date: 2018-03-15
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.008, car.2014-11-003, car.2014-11-008
// Description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\winlogon.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\wt.exe") and (action_process_image_command_line contains "sethc.exe" or action_process_image_command_line contains "utilman.exe" or action_process_image_command_line contains "osk.exe" or action_process_image_command_line contains "Magnify.exe" or action_process_image_command_line contains "Narrator.exe" or action_process_image_command_line contains "DisplaySwitch.exe"))
