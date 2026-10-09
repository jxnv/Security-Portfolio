// Title: GAC DLL Loaded Via Office Applications
// ID: 90217a70-13fc-48e4-b3db-0d836c5824ac
// Status: test
// Level: high
// Author: Antonlovesdnb
// Date: 2020-02-19
// Tags: attack.execution, attack.t1204.002
// Description: Detects any GAC DLL being loaded by an Office Product
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenoteim.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and ImageLoaded startswith "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL")
