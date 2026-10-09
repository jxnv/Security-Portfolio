// Title: Suspicious PROCEXP152.sys File Created In TMP
// ID: 3da70954-0f2c-4103-adff-b7440368f50e
// Status: test
// Level: medium
// Author: xknow (@xknow_infosec), xorxes (@xor_xes)
// Date: 2019-04-08
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder.
// This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\AppData\\Local\\Temp\\" and action_file_path endswith "PROCEXP152.sys") and not (((action_process_image_path contains "\\procexp64.exe" or action_process_image_path contains "\\procexp64a.exe" or action_process_image_path contains "\\procexp.exe" or action_process_image_path contains "\\procmon64.exe" or action_process_image_path contains "\\procmon64a.exe" or action_process_image_path contains "\\procmon.exe"))))
