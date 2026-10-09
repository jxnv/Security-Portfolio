// Title: UAC Bypass Using Windows Media Player - File
// ID: 68578b43-65df-4f81-9a9b-92f32711a951
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path startswith "C:\\Users\\" and action_file_path endswith "\\AppData\\Local\\Temp\\OskSupport.dll") or (action_process_image_path = "C:\\Windows\\system32\\DllHost.exe" and action_file_path = "C:\\Program Files\\Windows Media Player\\osk.exe"))
