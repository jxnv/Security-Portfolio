// Title: Suspicious Microsoft Office Child Process - MacOS
// ID: 69483748-1525-4a6c-95ca-90dc8d431b68
// Status: test
// Level: high
// Author: Sohan G (D4rkCiph3r)
// Date: 2023-01-31
// Tags: attack.execution, attack.persistence, attack.t1059.002, attack.t1137.002, attack.t1204.002
// Description: Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path contains "Microsoft Word" or actor_process_image_path contains "Microsoft Excel" or actor_process_image_path contains "Microsoft PowerPoint" or actor_process_image_path contains "Microsoft OneNote") and (action_process_image_path endswith "/bash" or action_process_image_path endswith "/curl" or action_process_image_path endswith "/dash" or action_process_image_path endswith "/fish" or action_process_image_path endswith "/osacompile" or action_process_image_path endswith "/osascript" or action_process_image_path endswith "/sh" or action_process_image_path endswith "/zsh" or action_process_image_path endswith "/python" or action_process_image_path endswith "/python3" or action_process_image_path endswith "/wget"))
