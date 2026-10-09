// Title: CLR DLL Loaded Via Office Applications
// ID: d13c43f0-f66b-4279-8b2c-5912077c1780
// Status: test
// Level: medium
// Author: Antonlovesdnb
// Date: 2020-02-19
// Tags: attack.execution, attack.t1204.002
// Description: Detects CLR DLL being loaded by an Office Product
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenoteim.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and ImageLoaded contains "\\clr.dll")
