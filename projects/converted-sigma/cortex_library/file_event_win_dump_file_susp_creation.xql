// Title: Potentially Suspicious DMP/HDMP File Creation
// ID: aba15bdd-657f-422a-bab3-ac2d2a0d6f1c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-07
// Tags: attack.stealth
// Description: Detects the creation of a file with the ".dmp"/".hdmp" extension by a shell or scripting application such as "cmd", "powershell", etc. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe") and (action_file_path endswith ".dmp" or action_file_path endswith ".dump" or action_file_path endswith ".hdmp"))
