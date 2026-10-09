// Title: Python Spawning Pretty TTY Via PTY Module
// ID: c4042d54-110d-45dd-a0e1-05c47822c937
// Status: test
// Level: medium
// Author: Nextron Systems
// Date: 2022-06-03
// Tags: attack.execution, attack.t1059
// Description: Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "import pty" or action_process_image_command_line contains "from pty ")) and (action_process_image_command_line contains "spawn") and (((action_process_image_path endswith "/python" or action_process_image_path endswith "/python2" or action_process_image_path endswith "/python3")) or ((action_process_image_path contains "/python2." or action_process_image_path contains "/python3."))))
