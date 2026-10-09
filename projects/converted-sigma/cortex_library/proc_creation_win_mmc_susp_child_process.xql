// Title: MMC Spawning Windows Shell
// ID: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
// Status: test
// Level: high
// Author: Karneades, Swisscom CSIRT
// Date: 2019-08-05
// Tags: attack.lateral-movement, attack.t1021.003
// Description: Detects a Windows command line executable started from MMC
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\mmc.exe") and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\regsvr32.exe")) or (action_process_image_path contains "\\BITSADMIN")))
