// Title: Suspicious File Created In PerfLogs
// ID: bbb7e38c-0b41-4a11-b306-d2a457b7ac2b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-05
// Tags: attack.execution, attack.t1059
// Description: Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path startswith "C:\\PerfLogs\\" and (action_file_path endswith ".7z" or action_file_path endswith ".bat" or action_file_path endswith ".bin" or action_file_path endswith ".chm" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".lnk" or action_file_path endswith ".ps1" or action_file_path endswith ".psm1" or action_file_path endswith ".py" or action_file_path endswith ".scr" or action_file_path endswith ".sys" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".zip"))
