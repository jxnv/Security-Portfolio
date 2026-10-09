// Title: Potential appverifUI.DLL Sideloading
// ID: ee6cea48-c5b6-4304-a332-10fc6446f484
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-20
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "appverifUI.dll"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\appverifUI.dll") and not (((action_process_image_path = "C:\\Windows\\SysWOW64\\appverif.exe" or action_process_image_path = "C:\\Windows\\System32\\appverif.exe") and (ImageLoaded startswith "C:\\Windows\\System32\\" or ImageLoaded startswith "C:\\Windows\\SysWOW64\\" or ImageLoaded startswith "C:\\Windows\\WinSxS\\"))))
