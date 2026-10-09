// Title: Potential PowerShell Obfuscation Via WCHAR/CHAR
// ID: e312efd0-35a1-407f-8439-b8d434b438a6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-07-09
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1027
// Description: Detects suspicious encoded character syntax often used for defense evasion
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "[char]0x" or action_process_image_command_line contains "(WCHAR)0x"))
