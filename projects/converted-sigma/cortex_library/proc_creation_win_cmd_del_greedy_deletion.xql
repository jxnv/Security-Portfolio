// Title: Greedy File Deletion Using Del
// ID: 204b17ae-4007-471b-917b-b917b315c5db
// Status: test
// Level: medium
// Author: frack113 , X__Junior (Nextron Systems)
// Date: 2021-12-02
// Tags: attack.stealth, attack.t1070.004
// Description: Detects execution of the "del" builtin command to remove files using greedy/wildcard expression. This is often used by malware to delete content of folders that perhaps contains the initial malware infection or to delete evidence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "del " or action_process_image_command_line contains "erase ")) and ((action_process_image_command_line contains "\\\\\\*.au3" or action_process_image_command_line contains "\\\\\\*.dll" or action_process_image_command_line contains "\\\\\\*.exe" or action_process_image_command_line contains "\\\\\\*.js")) and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")))
