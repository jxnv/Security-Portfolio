// Title: Python Spawning Pretty TTY on Windows
// ID: 480e7e51-e797-47e3-8d72-ebfce65b6d8d
// Status: test
// Level: high
// Author: Nextron Systems
// Date: 2022-06-03
// Tags: attack.execution, attack.t1059
// Description: Detects python spawning a pretty tty
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "python.exe" or action_process_image_path endswith "python3.exe" or action_process_image_path endswith "python2.exe")) and (((action_process_image_command_line contains "import pty" and action_process_image_command_line contains ".spawn(")) or (action_process_image_command_line contains "from pty import spawn")))
