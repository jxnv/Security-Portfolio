// Title: Suspicious Installer Package Child Process
// ID: e0cfaecd-602d-41af-988d-f6ccebb2af26
// Status: test
// Level: medium
// Author: Sohan G (D4rkCiph3r)
// Date: 2023-02-18
// Tags: attack.t1059, attack.t1059.007, attack.t1071, attack.t1071.001, attack.execution, attack.command-and-control
// Description: Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "/package_script_service" or actor_process_image_path endswith "/installer") and (action_process_image_path endswith "/sh" or action_process_image_path endswith "/bash" or action_process_image_path endswith "/dash" or action_process_image_path endswith "/python" or action_process_image_path endswith "/ruby" or action_process_image_path endswith "/perl" or action_process_image_path endswith "/php" or action_process_image_path endswith "/javascript" or action_process_image_path endswith "/osascript" or action_process_image_path endswith "/tclsh" or action_process_image_path endswith "/curl" or action_process_image_path endswith "/wget") and (action_process_image_command_line contains "preinstall" or action_process_image_command_line contains "postinstall"))
