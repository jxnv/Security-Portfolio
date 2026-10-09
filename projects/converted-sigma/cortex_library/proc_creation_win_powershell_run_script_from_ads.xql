// Title: Run PowerShell Script from ADS
// ID: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
// Status: test
// Level: high
// Author: Sergey Soldatov, Kaspersky Lab, oscd.community
// Date: 2019-10-30
// Tags: attack.stealth, attack.t1564.004
// Description: Detects PowerShell script execution from Alternate Data Stream (ADS)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and (action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "Get-Content" and action_process_image_command_line contains "-Stream"))
