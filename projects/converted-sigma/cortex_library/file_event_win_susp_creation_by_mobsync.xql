// Title: Created Files by Microsoft Sync Center
// ID: 409f8a98-4496-4aaa-818a-c931c0a8b832
// Status: test
// Level: medium
// Author: elhoim
// Date: 2022-04-28
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1218, attack.execution
// Description: This rule detects suspicious files created by Microsoft Sync Center (mobsync)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\mobsync.exe") and ((action_file_path endswith ".dll" or action_file_path endswith ".exe")))
