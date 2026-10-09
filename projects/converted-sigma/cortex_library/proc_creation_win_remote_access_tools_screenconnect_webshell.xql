// Title: Remote Access Tool - ScreenConnect Server Web Shell Execution
// ID: b19146a3-25d4-41b4-928b-1e2a92641b1b
// Status: test
// Level: high
// Author: Jason Rathbun (Blackpoint Cyber)
// Date: 2024-02-26
// Tags: attack.initial-access, attack.t1190
// Description: Detects potential web shell execution from the ScreenConnect server process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\ScreenConnect.Service.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\csc.exe"))
