// Title: HackTool - winPEAS Execution
// ID: 98b53e78-ebaf-46f8-be06-421aafd176d9
// Status: test
// Level: high
// Author: Georg Lauenstein (sure[secure])
// Date: 2022-09-19
// Tags: attack.privilege-escalation, attack.discovery, attack.t1082, attack.t1087, attack.t1046
// Description: WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on book.hacktricks.xyz
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "https://github.com/carlospolop/PEASS-ng/releases/latest/download/") or ((action_process_image_command_line contains " applicationsinfo" or action_process_image_command_line contains " browserinfo" or action_process_image_command_line contains " eventsinfo" or action_process_image_command_line contains " fileanalysis" or action_process_image_command_line contains " filesinfo" or action_process_image_command_line contains " processinfo" or action_process_image_command_line contains " servicesinfo" or action_process_image_command_line contains " windowscreds")) or ((actor_process_command_line endswith " -linpeas") or (action_process_image_command_line endswith " -linpeas")) or ((action_process_image_name = "winPEAS.exe") or ((action_process_image_path endswith "\\winPEASany_ofs.exe" or action_process_image_path endswith "\\winPEASany.exe" or action_process_image_path endswith "\\winPEASx64_ofs.exe" or action_process_image_path endswith "\\winPEASx64.exe" or action_process_image_path endswith "\\winPEASx86_ofs.exe" or action_process_image_path endswith "\\winPEASx86.exe"))))
