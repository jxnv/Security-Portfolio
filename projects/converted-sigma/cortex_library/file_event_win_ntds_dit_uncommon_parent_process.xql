// Title: NTDS.DIT Creation By Uncommon Parent Process
// ID: 4e7050dd-e548-483f-b7d6-527ab4fa784d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-11
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\ntds.dit") and (((actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\httpd.exe" or actor_process_image_path endswith "\\nginx.exe" or actor_process_image_path endswith "\\php-cgi.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\w3wp.exe" or actor_process_image_path endswith "\\wscript.exe")) or ((actor_process_image_path contains "\\apache" or actor_process_image_path contains "\\tomcat" or actor_process_image_path contains "\\AppData\\" or actor_process_image_path contains "\\Temp\\" or actor_process_image_path contains "\\Public\\" or actor_process_image_path contains "\\PerfLogs\\"))))
