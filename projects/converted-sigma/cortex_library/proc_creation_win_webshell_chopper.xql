// Title: Chopper Webshell Process Pattern
// ID: fa3c117a-bc0d-416e-a31b-0c0e80653efb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), MSTI (query)
// Date: 2022-10-01
// Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
// Description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "&ipconfig&echo" or action_process_image_command_line contains "&quser&echo" or action_process_image_command_line contains "&whoami&echo" or action_process_image_command_line contains "&c:&echo" or action_process_image_command_line contains "&cd&echo" or action_process_image_command_line contains "&dir&echo" or action_process_image_command_line contains "&echo [E]" or action_process_image_command_line contains "&echo [S]")) and ((action_process_image_path endswith "\\w3wp.exe") or (actor_process_image_path endswith "\\w3wp.exe")))
