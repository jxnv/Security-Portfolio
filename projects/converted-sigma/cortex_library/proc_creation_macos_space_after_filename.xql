// Title: Space After Filename - macOS
// ID: b6e2a2e3-2d30-43b1-a4ea-071e36595690
// Status: test
// Level: low
// Author: remotephone
// Date: 2021-11-20
// Tags: attack.stealth, attack.t1036.006
// Description: Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line endswith " ") or (action_process_image_path endswith " "))
