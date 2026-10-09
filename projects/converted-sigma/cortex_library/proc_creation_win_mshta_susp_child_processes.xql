// Title: Suspicious MSHTA Child Process
// ID: 03cc0c25-389f-4bf8-b48d-11878079f1ca
// Status: test
// Level: high
// Author: Michael Haag
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1218.005, car.2013-02-003, car.2013-03-001, car.2014-04-003
// Description: Detects a suspicious process spawning from an "mshta.exe" process, which could be indicative of a malicious HTA script execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\bitsadmin.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "wscript.exe" or action_process_image_name = "cscript.exe" or action_process_image_name = "Bash.exe" or action_process_image_name = "reg.exe" or action_process_image_name = "REGSVR32.EXE" or action_process_image_name = "bitsadmin.exe"))) and (actor_process_image_path endswith "\\mshta.exe"))
