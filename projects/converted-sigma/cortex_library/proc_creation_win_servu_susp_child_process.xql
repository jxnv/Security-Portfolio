// Title: Suspicious Serv-U Process Pattern
// ID: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-14
// Tags: attack.credential-access, attack.t1555, cve.2021-35211
// Description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\Serv-U.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\scriptrunner.exe"))
