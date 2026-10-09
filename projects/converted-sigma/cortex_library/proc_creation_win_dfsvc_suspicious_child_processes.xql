// Title: Potentially Suspicious Child Process Of ClickOnce Application
// ID: 67bc0e75-c0a9-4cfc-8754-84a505b63c04
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-12
// Tags: attack.execution, attack.stealth
// Description: Detects potentially suspicious child processes of a ClickOnce deployment application
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path contains "\\AppData\\Local\\Apps\\2.0\\" and (action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\explorer.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\nltest.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\werfault.exe" or action_process_image_path endswith "\\wscript.exe"))
