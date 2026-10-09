// Title: Suspicious WmiPrvSE Child Process
// ID: 8a582fe2-0882-4b89-a82a-da6b2dc32937
// Status: test
// Level: high
// Author: Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.execution, attack.stealth, attack.t1047, attack.t1204.002, attack.t1218.010
// Description: Detects suspicious and uncommon child processes of WmiPrvSE
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\wbem\\WmiPrvSE.exe") and (((action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\verclsid.exe" or action_process_image_path endswith "\\wscript.exe")) or (action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "cscript" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "pwsh" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "wscript"))) and not (((action_process_image_path endswith "\\msiexec.exe" and action_process_image_command_line contains "/i ") or (action_process_image_path endswith "\\WerFault.exe") or (action_process_image_path endswith "\\WmiPrvSE.exe"))))
