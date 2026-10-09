// Title: Potential Process Hollowing Activity
// ID: c4b890e5-8d8c-4496-8c66-c805753817cd
// Status: test
// Level: medium
// Author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Sittikorn S
// Date: 2022-01-25
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055.012
// Description: Detects when a memory process image does not match the disk image, indicative of process hollowing.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Type = "Image is replaced") and not (((action_process_image_path contains ":\\Program Files (x86)" or action_process_image_path contains ":\\Program Files\\" or action_process_image_path contains ":\\Windows\\System32\\wbem\\WMIADAP.exe" or action_process_image_path contains ":\\Windows\\SysWOW64\\wbem\\WMIADAP.exe"))) and not (((action_process_image_path endswith "\\WindowsApps\\MicrosoftEdge.exe") or (action_process_image_path contains "\\AppData\\Local\\Programs\\Opera\\" and action_process_image_path endswith "\\opera.exe"))))
