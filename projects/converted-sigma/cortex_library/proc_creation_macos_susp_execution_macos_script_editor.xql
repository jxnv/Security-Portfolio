// Title: Suspicious Execution via macOS Script Editor
// ID: 6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4
// Status: test
// Level: medium
// Author: Tim Rauch (rule), Elastic (idea)
// Date: 2022-10-21
// Tags: attack.defense-impairment, attack.t1566, attack.t1566.002, attack.initial-access, attack.t1059, attack.t1059.002, attack.t1204, attack.t1204.001, attack.execution, attack.persistence, attack.t1553
// Description: Detects when the macOS Script Editor utility spawns an unusual child process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/curl" or action_process_image_path endswith "/bash" or action_process_image_path endswith "/sh" or action_process_image_path endswith "/zsh" or action_process_image_path endswith "/dash" or action_process_image_path endswith "/fish" or action_process_image_path endswith "/osascript" or action_process_image_path endswith "/mktemp" or action_process_image_path endswith "/chmod" or action_process_image_path endswith "/php" or action_process_image_path endswith "/nohup" or action_process_image_path endswith "/openssl" or action_process_image_path endswith "/plutil" or action_process_image_path endswith "/PlistBuddy" or action_process_image_path endswith "/xattr" or action_process_image_path endswith "/sqlite" or action_process_image_path endswith "/funzip" or action_process_image_path endswith "/popen")) or ((action_process_image_path contains "python" or action_process_image_path contains "perl"))) and (actor_process_image_path endswith "/Script Editor"))
