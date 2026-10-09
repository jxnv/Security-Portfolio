// Title: Potential Waveedit.DLL Sideloading
// ID: 71b31e99-9ad0-47d4-aeb5-c0ca3928eeeb
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-14
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "waveedit.dll", which is part of the Nero WaveEditor audio editing software.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\waveedit.dll") and not (((action_process_image_path = "C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe" or action_process_image_path = "C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe") and (ImageLoaded startswith "C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\" or ImageLoaded startswith "C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\"))))
