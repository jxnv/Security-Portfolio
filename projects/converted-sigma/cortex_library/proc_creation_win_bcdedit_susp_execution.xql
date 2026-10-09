// Title: Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
// ID: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
// Status: test
// Level: medium
// Author: @neu5ron
// Date: 2019-02-07
// Tags: attack.stealth, attack.t1070, attack.persistence, attack.t1542.003
// Description: Detects potential malicious and unauthorized usage of bcdedit.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "delete" or action_process_image_command_line contains "deletevalue" or action_process_image_command_line contains "import" or action_process_image_command_line contains "safeboot" or action_process_image_command_line contains "network")) and ((action_process_image_path endswith "\\bcdedit.exe") or (action_process_image_name = "bcdedit.exe")))
