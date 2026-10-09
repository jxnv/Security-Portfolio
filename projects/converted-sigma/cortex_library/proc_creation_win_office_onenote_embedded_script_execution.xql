// Title: OneNote.EXE Execution of Malicious Embedded Scripts
// ID: 84b1706c-932a-44c4-ae28-892b28a25b94
// Status: test
// Level: high
// Author: @kostastsale
// Date: 2023-02-02
// Tags: attack.stealth, attack.t1218.001
// Description: Detects the execution of malicious OneNote documents that contain embedded scripts.
// When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\onenote.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe") and (action_process_image_command_line contains "\\exported\\" or action_process_image_command_line contains "\\onenoteofflinecache_files\\"))
