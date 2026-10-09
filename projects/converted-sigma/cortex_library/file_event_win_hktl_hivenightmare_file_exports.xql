// Title: HackTool - Typical HiveNightmare SAM File Export
// ID: 6ea858a8-ba71-4a12-b2cc-5d83312404c7
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-23
// Tags: attack.credential-access, attack.t1552.001, cve.2021-36934
// Description: Detects files written by the different tools that exploit HiveNightmare
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "\\hive_sam_" or action_file_path contains "\\SAM-2021-" or action_file_path contains "\\SAM-2022-" or action_file_path contains "\\SAM-2023-" or action_file_path contains "\\SAM-haxx" or action_file_path contains "\\Sam.save")) or (action_file_path = "C:\\windows\\temp\\sam"))
