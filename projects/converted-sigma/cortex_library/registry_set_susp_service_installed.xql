// Title: Suspicious Service Installed
// ID: f2485272-a156-4773-82d7-1d178bc4905b
// Status: test
// Level: medium
// Author: xknow (@xknow_infosec), xorxes (@xor_xes)
// Date: 2019-04-08
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders.
// Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject = "HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" or TargetObject = "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath")) and not (((action_process_image_path endswith "\\procexp64.exe" or action_process_image_path endswith "\\procexp64a.exe" or action_process_image_path endswith "\\procexp.exe" or action_process_image_path endswith "\\procmon64.exe" or action_process_image_path endswith "\\procmon64a.exe" or action_process_image_path endswith "\\procmon.exe" or action_process_image_path endswith "\\handle.exe" or action_process_image_path endswith "\\handle64.exe" or action_process_image_path endswith "\\handle64a.exe") and Details contains "\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS")))
