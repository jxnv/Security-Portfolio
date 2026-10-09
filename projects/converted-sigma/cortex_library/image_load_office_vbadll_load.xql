// Title: VBA DLL Loaded Via Office Application
// ID: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
// Status: test
// Level: high
// Author: Antonlovesdnb
// Date: 2020-02-19
// Tags: attack.execution, attack.t1204.002
// Description: Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenoteim.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and (ImageLoaded endswith "\\VBE7.DLL" or ImageLoaded endswith "\\VBEUI.DLL" or ImageLoaded endswith "\\VBE7INTL.DLL"))
