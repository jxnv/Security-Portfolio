// Title: Scripting/CommandLine Process Spawned Regsvr32
// ID: ab37a6ec-6068-432b-a64e-2c7bf95b1d22
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-26
// Tags: attack.stealth, attack.t1218.010
// Description: Detects various command line and scripting engines/processes such as "PowerShell", "Wscript", "Cmd", etc. spawning a "regsvr32" instance.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\powershell_ise.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\wscript.exe") and action_process_image_path endswith "\\regsvr32.exe") and not ((actor_process_image_path = "C:\\Windows\\System32\\cmd.exe" and action_process_image_command_line endswith " /s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll")))
