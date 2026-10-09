// Title: HackTool - RedMimicry Winnti Playbook Execution
// ID: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
// Status: test
// Level: high
// Author: Alexander Rausch
// Date: 2020-06-24
// Tags: attack.execution, attack.stealth, attack.t1106, attack.t1059.003, attack.t1218.011
// Description: Detects actions caused by the RedMimicry Winnti playbook a automated breach emulations utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\cmd.exe") and (action_process_image_command_line contains "gthread-3.6.dll" or action_process_image_command_line contains "\\Windows\\Temp\\tmp.bat" or action_process_image_command_line contains "sigcmm-2.4.dll"))
