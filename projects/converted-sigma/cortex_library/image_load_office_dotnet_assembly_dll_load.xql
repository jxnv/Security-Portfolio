// Title: DotNET Assembly DLL Loaded Via Office Application
// ID: ff0f2b05-09db-4095-b96d-1b75ca24894a
// Status: test
// Level: medium
// Author: Antonlovesdnb
// Date: 2020-02-19
// Tags: attack.execution, attack.t1204.002
// Description: Detects any assembly DLL being loaded by an Office Product
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenoteim.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and ImageLoaded startswith "C:\\Windows\\assembly\\")
