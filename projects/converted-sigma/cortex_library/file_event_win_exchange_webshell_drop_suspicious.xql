// Title: Suspicious File Drop by Exchange
// ID: 6b269392-9eba-40b5-acb6-55c882b20ba6
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-10-04
// Tags: attack.persistence, attack.t1190, attack.initial-access, attack.t1505.003
// Description: Detects suspicious file type dropped by an Exchange component in IIS
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\w3wp.exe" and action_process_image_command_line contains "MSExchange") and ((action_file_path endswith ".aspx" or action_file_path endswith ".asp" or action_file_path endswith ".ashx" or action_file_path endswith ".ps1" or action_file_path endswith ".bat" or action_file_path endswith ".exe" or action_file_path endswith ".dll" or action_file_path endswith ".vbs")))
