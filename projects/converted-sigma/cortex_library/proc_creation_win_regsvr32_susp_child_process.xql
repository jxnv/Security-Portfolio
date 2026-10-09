// Title: Potentially Suspicious Child Process Of Regsvr32
// ID: 6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca
// Status: test
// Level: high
// Author: elhoim, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-05-05
// Tags: attack.stealth, attack.t1218.010
// Description: Detects potentially suspicious child processes of "regsvr32.exe".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\regsvr32.exe" and (action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\explorer.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\nltest.exe" or action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\werfault.exe" or action_process_image_path endswith "\\wscript.exe")) and not ((action_process_image_path endswith "\\werfault.exe" and action_process_image_command_line contains " -u -p ")))
