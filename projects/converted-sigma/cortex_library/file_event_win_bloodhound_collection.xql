// Title: BloodHound Collection Files
// ID: 02773bed-83bf-469f-b7ff-e676e7d78bab
// Status: test
// Level: high
// Author: C.J. May
// Date: 2022-08-09
// Tags: attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001
// Description: Detects default file names outputted by the BloodHound collection tool SharpHound
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "BloodHound.zip" or action_file_path endswith "_computers.json" or action_file_path endswith "_containers.json" or action_file_path endswith "_gpos.json" or action_file_path endswith "_groups.json" or action_file_path endswith "_ous.json" or action_file_path endswith "_users.json")) and not ((action_process_image_path endswith "\\svchost.exe" and action_file_path startswith "C:\\Program Files\\WindowsApps\\Microsoft." and action_file_path endswith "\\pocket_containers.json")))
