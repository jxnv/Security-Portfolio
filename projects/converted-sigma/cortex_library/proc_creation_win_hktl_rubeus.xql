// Title: HackTool - Rubeus Execution
// ID: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
// Status: stable
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2018-12-19
// Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
// Description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\Rubeus.exe") or (action_process_image_name = "Rubeus.exe") or (Description = "Rubeus") or ((action_process_image_command_line contains "asreproast " or action_process_image_command_line contains "dump /service:krbtgt " or action_process_image_command_line contains "dump /luid:0x" or action_process_image_command_line contains "kerberoast " or action_process_image_command_line contains "createnetonly /program:" or action_process_image_command_line contains "ptt /ticket:" or action_process_image_command_line contains "/impersonateuser:" or action_process_image_command_line contains "renew /ticket:" or action_process_image_command_line contains "asktgt /user:" or action_process_image_command_line contains "harvest /interval:" or action_process_image_command_line contains "s4u /user:" or action_process_image_command_line contains "s4u /ticket:" or action_process_image_command_line contains "hash /password:" or action_process_image_command_line contains "golden /aes256:" or action_process_image_command_line contains "silver /user:")))
