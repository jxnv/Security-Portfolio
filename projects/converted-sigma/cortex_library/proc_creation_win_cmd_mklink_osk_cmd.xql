// Title: Potential Privilege Escalation Using Symlink Between Osk and Cmd
// ID: e9b61244-893f-427c-b287-3e708f321c6b
// Status: test
// Level: high
// Author: frack113
// Date: 2022-12-11
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.008
// Description: Detects the creation of a symbolic link between "cmd.exe" and the accessibility on-screen keyboard binary (osk.exe) using "mklink". This technique provides an elevated command prompt to the user from the login screen without the need to log in.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "mklink" and action_process_image_command_line contains "\\osk.exe" and action_process_image_command_line contains "\\cmd.exe")) and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")))
