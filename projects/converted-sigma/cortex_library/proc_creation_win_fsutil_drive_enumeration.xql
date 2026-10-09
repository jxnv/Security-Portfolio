// Title: Fsutil Drive Enumeration
// ID: 63de06b9-a385-40b5-8b32-73f2b9ef84b6
// Status: test
// Level: low
// Author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
// Date: 2022-03-29
// Tags: attack.discovery, attack.t1120
// Description: Attackers may leverage fsutil to enumerated connected drives.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "drives") and ((action_process_image_path endswith "\\fsutil.exe") or (action_process_image_name = "fsutil.exe")))
