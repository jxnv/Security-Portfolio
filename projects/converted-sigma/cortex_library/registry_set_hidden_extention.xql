// Title: Registry Modification to Hidden File Extension
// ID: 5df86130-4e95-4a54-90f7-26541b40aec2
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-22
// Tags: attack.persistence, attack.t1137
// Description: Hides the file extension through modification of the registry
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden" and Details = "DWORD (0x00000002)") or (TargetObject endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" and Details = "DWORD (0x00000001)"))
