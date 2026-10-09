// Title: Suspicious BitLocker Access Agent Update Utility Execution
// ID: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
// Status: experimental
// Level: high
// Author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-10-18
// Tags: attack.stealth, attack.t1218, attack.lateral-movement, attack.t1021.003
// Description: Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
// Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\baaupdate.exe" and (action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe"))
