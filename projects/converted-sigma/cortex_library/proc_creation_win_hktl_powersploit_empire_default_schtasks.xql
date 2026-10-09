// Title: HackTool - Default PowerSploit/Empire Scheduled Task Creation
// ID: 56c217c3-2de2-479b-990f-5c109ba8458f
// Status: test
// Level: high
// Author: Markus Neis, @Karneades
// Date: 2018-03-06
// Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.s0111, attack.g0022, attack.g0060, car.2013-08-001, attack.t1053.005, attack.t1059.001
// Description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and action_process_image_path endswith "\\schtasks.exe" and (action_process_image_command_line contains "/Create" and action_process_image_command_line contains "powershell.exe -NonI" and action_process_image_command_line contains "/TN Updater /TR") and (action_process_image_command_line contains "/SC ONLOGON" or action_process_image_command_line contains "/SC DAILY /ST" or action_process_image_command_line contains "/SC ONIDLE" or action_process_image_command_line contains "/SC HOURLY"))
