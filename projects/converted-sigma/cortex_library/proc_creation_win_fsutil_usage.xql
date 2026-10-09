// Title: Fsutil Suspicious Invocation
// ID: add64136-62e5-48ea-807e-88638d02df1e
// Status: stable
// Level: high
// Author: Ecco, E.M. Anhaus, oscd.community
// Date: 2019-09-26
// Tags: attack.impact, attack.stealth, attack.t1070, attack.t1485
// Description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size, etc).
// Might be used by ransomwares during the attack (seen by NotPetya and others).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "deletejournal" or action_process_image_command_line contains "createjournal" or action_process_image_command_line contains "setZeroData")) and ((action_process_image_path endswith "\\fsutil.exe") or (action_process_image_name = "fsutil.exe")))
