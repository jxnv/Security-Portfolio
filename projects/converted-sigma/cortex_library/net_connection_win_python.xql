// Title: Python Initiated Connection
// ID: bef0bc5a-b9ae-425d-85c6-7b2d705980c6
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-10
// Tags: attack.discovery, attack.t1046
// Description: Detects a Python process initiating a network connection. While this often relates to package installation, it can also indicate a potential malicious script communicating with a C&C server.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and (action_process_image_path contains "\\python" and action_process_image_path contains ".exe")) and not (((action_remote_ip = "127.0.0.1" and action_local_ip = "127.0.0.1") or ((action_process_image_command_line contains "pip.exe" and action_process_image_command_line contains "install")))) and not (((actor_process_image_path = "C:\\ProgramData\\Anaconda3\\Scripts\\conda.exe" and (action_process_image_command_line contains ":\\ProgramData\\Anaconda3\\Scripts\\conda-script.py" and action_process_image_command_line contains "update")) or (actor_process_image_path = "C:\\ProgramData\\Anaconda3\\python.exe" and action_process_image_command_line contains "C:\\ProgramData\\Anaconda3\\Scripts\\jupyter-notebook-script.py"))))
