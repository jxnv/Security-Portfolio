// Title: Potential ShellDispatch.DLL Sideloading
// ID: 844f8eb2-610b-42c8-89a4-47596e089663
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-20
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "ShellDispatch.dll"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\ShellDispatch.dll") and not ((((ImageLoaded contains ":\\Users\\" and ImageLoaded contains "\\AppData\\Local\\Temp\\")) or (ImageLoaded contains ":\\Windows\\Temp\\"))))
