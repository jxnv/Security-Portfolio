// Title: Python Inline Command Execution
// ID: 899133d5-4d7c-4a7f-94ee-27355c879d90
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-02
// Tags: attack.execution, attack.t1059
// Description: Detects execution of python using the "-c" flag. This is could be used as a way to launch a reverse shell or execute live python code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -c") and ((action_process_image_name = "python.exe") or ((action_process_image_path endswith "python.exe" or action_process_image_path endswith "python3.exe" or action_process_image_path endswith "python2.exe")))) and not ((((actor_process_image_path startswith "C:\\Program Files\\Python" or actor_process_image_path startswith "C:\\Program Files (x86)\\Python") and actor_process_image_path endswith "\\python.exe" and actor_process_command_line contains "-E -s -m ensurepip -U --default-pip") or ((actor_process_image_path startswith "C:\\Program Files\\Python" or actor_process_image_path startswith "C:\\Program Files (x86)\\Python") and (action_process_image_command_line contains "-W ignore::DeprecationWarning" and action_process_image_command_line contains "['install', '--no-cache-dir', '--no-index', '--find-links'," and action_process_image_command_line contains "'--upgrade', 'pip'")))) and not ((((action_process_image_command_line contains "<pip-setuptools-caller>" and action_process_image_command_line contains "exec(compile(")) or ((actor_process_image_path endswith "\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe") or ((actor_process_image_path = "C:\\Program Files\\Microsoft VS Code\\Code.exe" or actor_process_image_path = "C:\\Program Files (x86)\\Microsoft VS Code\\Code.exe"))))))
