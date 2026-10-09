// Title: Python One-Liners with Base64 Decoding - Linux
// ID: 55e862a8-dd9c-4651-807a-f21fcad56716
// Status: experimental
// Level: high
// Author: Hugh Ryan (HueCodes), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-03-09
// Tags: attack.execution, attack.stealth, attack.t1059.006, attack.t1027.010
// Description: Detects the use of Python's base64 decoding functions in command line executions on Linux systems.
// Malicious scripts often use python one-liners to decode and execute base64-encoded payloads, which is a common technique for obfuscation and evasion.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "import" and action_process_image_command_line contains "base64" and action_process_image_command_line contains " -c") and (action_process_image_command_line contains ".decode" or action_process_image_command_line contains "b16decode" or action_process_image_command_line contains "b32decode" or action_process_image_command_line contains "b32hexdecode" or action_process_image_command_line contains "b64decode" or action_process_image_command_line contains "b85decode" or action_process_image_command_line contains "z85decode")) and (action_process_image_path contains "/python"))
