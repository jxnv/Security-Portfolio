// Title: Potential EACore.DLL Sideloading
// ID: edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-08-03
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "EACore.dll"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\EACore.dll") and not (((action_process_image_path contains "C:\\Program Files\\Electronic Arts\\EA Desktop\\" and action_process_image_path contains "\\EACoreServer.exe") and ImageLoaded startswith "C:\\Program Files\\Electronic Arts\\EA Desktop\\")))
