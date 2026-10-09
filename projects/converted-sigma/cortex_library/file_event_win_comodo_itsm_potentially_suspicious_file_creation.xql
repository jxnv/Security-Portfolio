// Title: Potentially Suspicious File Creation by OpenEDR's ITSMService
// ID: 9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d
// Status: experimental
// Level: medium
// Author: @kostastsale
// Date: 2026-02-19
// Tags: attack.command-and-control, attack.t1105, attack.lateral-movement, attack.t1570, attack.t1219
// Description: Detects the creation of potentially suspicious files by OpenEDR's ITSMService process.
// The ITSMService is responsible for remote management operations and can create files on the system through the Process Explorer or file management features.
// While legitimate for IT operations, creation of executable or script files could indicate unauthorized file uploads, data staging, or malicious file deployment.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\COMODO\\Endpoint Manager\\ITSMService.exe") and ((action_file_path endswith ".7z" or action_file_path endswith ".bat" or action_file_path endswith ".cmd" or action_file_path endswith ".com" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".js" or action_file_path endswith ".pif" or action_file_path endswith ".ps1" or action_file_path endswith ".rar" or action_file_path endswith ".scr" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".zip")))
