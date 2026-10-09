// Title: Suspicious Child Process Of Wermgr.EXE
// ID: 396f6630-f3ac-44e3-bfc8-1b161bc00c4e
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-10-14
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1036
// Description: Detects suspicious Windows Error Reporting manager (wermgr.exe) child process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\wermgr.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\ipconfig.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\netstat.exe" or action_process_image_path endswith "\\nslookup.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\wscript.exe")) and not ((action_process_image_path endswith "\\rundll32.exe" and (action_process_image_command_line contains "C:\\Windows\\system32\\WerConCpl.dll" and action_process_image_command_line contains "LaunchErcApp ") and (action_process_image_command_line contains "-queuereporting" or action_process_image_command_line contains "-responsepester"))))
