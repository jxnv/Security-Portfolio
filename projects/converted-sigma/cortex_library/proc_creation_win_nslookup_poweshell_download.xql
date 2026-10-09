// Title: Nslookup PowerShell Download Cradle - ProcessCreation
// ID: 1b3b01c7-84e9-4072-86e5-fc285a41ff23
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-05
// Tags: attack.stealth
// Description: Detects suspicious powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains " -q=txt " or action_process_image_command_line contains " -querytype=txt ")) and ((action_process_image_path contains "\\nslookup.exe") or (action_process_image_name = "\\nslookup.exe")))
