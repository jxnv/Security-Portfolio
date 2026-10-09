// Title: Potential DLL Sideloading Using Coregen.exe
// ID: 0fa66f66-e3f6-4a9c-93f8-4f2610b00171
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-12-31
// Tags: attack.privilege-escalation, attack.stealth, attack.t1218, attack.t1055
// Description: Detect usage of the "coregen.exe" (Microsoft CoreCLR Native Image Generator) binary to sideload arbitrary DLLs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\coregen.exe") and not (((ImageLoaded startswith "C:\\Program Files (x86)\\Microsoft Silverlight\\" or ImageLoaded startswith "C:\\Program Files\\Microsoft Silverlight\\" or ImageLoaded startswith "C:\\Windows\\System32\\" or ImageLoaded startswith "C:\\Windows\\SysWOW64\\"))))
