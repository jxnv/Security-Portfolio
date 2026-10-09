// Title: Potential SmadHook.DLL Sideloading
// ID: 24b6cf51-6122-469e-861a-22974e9c1e5b
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-01
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL sideloading of "SmadHook.dll", a DLL used by SmadAV antivirus
// Converted by: Sigma Universal SIEM/EDR CLI

(((ImageLoaded="*\\SmadHook32c.dll" OR ImageLoaded="*\\SmadHook64c.dll")) AND NOT (((Image == "C:\\Program Files (x86)\\SMADAV\\SmadavProtect32.exe" OR Image == "C:\\Program Files (x86)\\SMADAV\\SmadavProtect64.exe" OR Image == "C:\\Program Files\\SMADAV\\SmadavProtect32.exe" OR Image == "C:\\Program Files\\SMADAV\\SmadavProtect64.exe") AND (ImageLoaded="C:\\Program Files (x86)\\SMADAV\\*" OR ImageLoaded="C:\\Program Files\\SMADAV\\*"))))
