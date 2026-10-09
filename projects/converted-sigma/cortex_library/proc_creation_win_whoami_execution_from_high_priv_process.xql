// Title: Whoami.EXE Execution From Privileged Process
// ID: 79ce34ca-af29-4d0e-b832-fc1b377020db
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov
// Date: 2022-01-28
// Tags: attack.privilege-escalation, attack.discovery, attack.t1033
// Description: Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "whoami.exe") or (action_process_image_path endswith "\\whoami.exe")) and ((action_process_username contains "AUTHORI" or action_process_username contains "AUTORI" or action_process_username contains "TrustedInstaller")))
