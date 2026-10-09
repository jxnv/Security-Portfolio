// Title: Python WebServer Execution - Linux
// ID: 3f0f5957-04f8-4792-ad89-192b0303bde6
// Status: experimental
// Level: medium
// Author: Mohamed LAKRI
// Date: 2025-10-17
// Tags: attack.exfiltration, attack.t1048.003
// Description: Detects the execution of Python web servers via command line interface (CLI).
// After gaining access to target systems, adversaries may use Python's built-in HTTP server modules to quickly establish a web server without requiring additional software.
// This technique is commonly used in post-exploitation scenarios as it provides a simple method for transferring files between the compromised host and attacker-controlled systems.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/python" or action_process_image_path endswith "/python2" or action_process_image_path endswith "/python3")) or ((action_process_image_path contains "/python2." or action_process_image_path contains "/python3."))) and ((action_process_image_command_line contains "http.server" or action_process_image_command_line contains "SimpleHTTPServer")))
