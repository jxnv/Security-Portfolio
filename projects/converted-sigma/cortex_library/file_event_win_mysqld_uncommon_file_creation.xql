// Title: Uncommon File Creation By Mysql Daemon Process
// ID: c61daa90-3c1e-4f18-af62-8f288b5c9aaf
// Status: test
// Level: high
// Author: Joseph Kamau
// Date: 2024-05-27
// Tags: attack.stealth
// Description: Detects the creation of files with scripting or executable extensions by Mysql daemon.
// Which could be an indicator of "User Defined Functions" abuse to download malware.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\mysqld.exe" or action_process_image_path endswith "\\mysqld-nt.exe") and (action_file_path endswith ".bat" or action_file_path endswith ".dat" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".ps1" or action_file_path endswith ".psm1" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs"))
