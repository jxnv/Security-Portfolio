// Title: Security Privileges Enumeration Via Whoami.EXE
// ID: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-05-05
// Tags: attack.privilege-escalation, attack.discovery, attack.t1033
// Description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " /priv" or action_process_image_command_line contains " -priv")) and ((action_process_image_path endswith "\\whoami.exe") or (action_process_image_name = "whoami.exe")))
