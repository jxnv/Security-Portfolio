// Title: Process Monitor Driver Creation By Non-Sysinternals Binary
// ID: a05baa88-e922-4001-bc4d-8738135f27de
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-05
// Tags: attack.persistence, attack.privilege-escalation, attack.t1068
// Description: Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\procmon" and action_file_path endswith ".sys") and not (((action_process_image_path endswith "\\procmon.exe" or action_process_image_path endswith "\\procmon64.exe" or action_process_image_path endswith "\\procmon64a.exe"))))
