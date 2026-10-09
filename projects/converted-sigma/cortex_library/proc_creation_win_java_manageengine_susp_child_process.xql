// Title: Suspicious Child Process Of Manage Engine ServiceDesk
// ID: cea2b7ea-792b-405f-95a1-b903ea06458f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2023-01-18
// Tags: attack.command-and-control, attack.t1102
// Description: Detects suspicious child processes of the "Manage Engine ServiceDesk Plus" Java web service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path contains "\\ManageEngine\\ServiceDesk\\" and actor_process_image_path contains "\\java.exe") and (action_process_image_path endswith "\\AppVLP.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\mftrace.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\query.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\scrcons.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe")) and not (((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe") and action_process_image_command_line contains " stop")))
