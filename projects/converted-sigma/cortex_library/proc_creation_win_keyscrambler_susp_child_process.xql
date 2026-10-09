// Title: Potentially Suspicious Child Process of KeyScrambler.exe
// ID: ca5583e9-8f80-46ac-ab91-7f314d13b984
// Status: test
// Level: medium
// Author: Swachchhanda Shrawan Poudel
// Date: 2024-05-13
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.stealth, attack.t1203, attack.t1574.001
// Description: Detects potentially suspicious child processes of KeyScrambler.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "cscript.exe" or action_process_image_name = "mshta.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "regsvr32.exe" or action_process_image_name = "RUNDLL32.EXE" or action_process_image_name = "wscript.exe"))) and (actor_process_image_path endswith "\\KeyScrambler.exe"))
