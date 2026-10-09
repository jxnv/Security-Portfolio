// Title: Suspicious PowerShell Parent Process
// ID: 754ed792-634f-40ae-b3bc-e0448d33f695
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Harish Segar
// Date: 2020-03-20
// Tags: attack.execution, attack.t1059.001
// Description: Detects a suspicious or uncommon parent processes of PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path contains "tomcat") or ((actor_process_image_path endswith "\\amigo.exe" or actor_process_image_path endswith "\\browser.exe" or actor_process_image_path endswith "\\chrome.exe" or actor_process_image_path endswith "\\firefox.exe" or actor_process_image_path endswith "\\httpd.exe" or actor_process_image_path endswith "\\iexplore.exe" or actor_process_image_path endswith "\\jbosssvc.exe" or actor_process_image_path endswith "\\microsoftedge.exe" or actor_process_image_path endswith "\\microsoftedgecp.exe" or actor_process_image_path endswith "\\MicrosoftEdgeSH.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\nginx.exe" or actor_process_image_path endswith "\\outlook.exe" or actor_process_image_path endswith "\\php-cgi.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\safari.exe" or actor_process_image_path endswith "\\services.exe" or actor_process_image_path endswith "\\sqlagent.exe" or actor_process_image_path endswith "\\sqlserver.exe" or actor_process_image_path endswith "\\sqlservr.exe" or actor_process_image_path endswith "\\vivaldi.exe" or actor_process_image_path endswith "\\w3wp.exe"))) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_command_line contains "/c powershell" or action_process_image_command_line contains "/c pwsh")) or (Description = "Windows PowerShell") or (Product = "PowerShell Core 6") or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
